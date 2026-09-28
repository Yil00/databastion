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
//! Every input is first stripped of control / format characters and
//! NFKC-folded, so compatibility forms (fullwidth `４１１１`, `＠`, `．`,
//! `＿`, mathematical `𝟎`) go through the same rules as ASCII.
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
//! - percent-encoded bytes (`%40`) and `%uXXXX` escapes make a segment a
//!   value, and `%40` / `%u0040` are read as an `@`; password-hash prefixes (`$2b$`, `$argon2`…) mask the
//!   hash to its end; AWS key ids split by separators are found;
//! - digit runs split by single separators (`.`, `_`, `-`, space, `+`) with
//!   more than [`MAX_INDEX_DIGITS`] digits in total are values
//!   (`ab0612.34.5678`);
//! - segments that look like values become `*`: long numeric runs,
//!   characters the pattern forbids (`@`, `=`, `:`…), UUID / long hex keys,
//!   and words from a small list of common first names
//!   (`archive_lucas_martin`, `ou=Oliver Martin`), see [`is_first_name`];
//! - an LDAP entry DN is reduced to its parent container, attribute types
//!   are lowercased;
//! - anything that still does not conform becomes `*`, and so does a name
//!   with a run of more than [`MAX_INDEX_DIGITS`] or more than
//!   [`MAX_TOTAL_DIGITS`] numeric characters in total, in any script
//!   (CJK ideographic digits `零〇一二三四五六七八九` and financial
//!   numerals `壹贰叁肆伍陆柒捌玖` included, see [`is_numeric_like`]);
//! - an LDAP DN value that is empty or BER-encoded (`#…`) becomes `*`.
//!
//! Known gap: a surname alone, or a first name missing from the list, is
//! not recognized (`archive_martin`). No detector recognizes arbitrary
//! person names in identifiers.

use std::fmt;
use std::ops::Range;

use crate::detect;
use crate::hints::word_tokens;
use crate::id::ClassifierId;
use unicode_normalization::UnicodeNormalization;

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
/// Most numeric characters (any script) a normalized name may keep in
/// total. Array indices are `[]` and carry none, so only digits kept inside
/// names count. 8 is the shortest phone number the detectors know, so a
/// value spread over several segments (`a.x061234.y5678`, 10 digits) never
/// survives, even glued to letters.
pub const MAX_TOTAL_DIGITS: usize = 8;
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

    /// Final gate: the contract `Identifier` (pattern and `not` rule), no
    /// run of more than [`MAX_INDEX_DIGITS`] numeric characters in any
    /// script, at most [`MAX_TOTAL_DIGITS`] numeric characters in the whole
    /// name (both counted with [`is_numeric_like`]), no percent-encoded
    /// byte or `%uXXXX` escape; `*` otherwise.
    fn checked(candidate: String) -> Self {
        let digits = candidate.chars().filter(|c| is_numeric_like(*c)).count();
        if conforms(&candidate)
            && longest_digit_run(&candidate) <= MAX_INDEX_DIGITS
            && digits <= MAX_TOTAL_DIGITS
            && !has_percent_escape(&candidate)
        {
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

/// CJK numerals that `char::is_numeric` does not report (they are letters,
/// `Lo`, in Unicode; `〇` is already numeric): the ideographic digits
/// `零〇一二三四五六七八九`, the financial forms `壹贰叁肆伍陆柒捌玖`
/// (and the traditional `貳參陸`), `两` / `兩` (two) and `拾` (ten). Hangul
/// numerals are left out on purpose: they are ordinary syllables.
const CJK_DIGITS: [char; 26] = [
    '零', '〇', '一', '二', '三', '四', '五', '六', '七', '八', '九', '壹', '贰', '叁', '肆', '伍',
    '陆', '柒', '捌', '玖', '貳', '參', '陸', '两', '兩', '拾',
];

/// Whether `c` counts as a digit for the digit bounds: a numeric character
/// in any script (`char::is_numeric`: ASCII, fullwidth, Arabic-Indic,
/// mathematical digits…) or a CJK numeral ([`CJK_DIGITS`]), so a number
/// written with them is bounded like any other.
#[must_use]
pub fn is_numeric_like(c: char) -> bool {
    c.is_numeric() || CJK_DIGITS.contains(&c)
}

/// Longest run of consecutive digits, in any script ([`is_numeric_like`]).
#[must_use]
pub fn longest_digit_run(s: &str) -> usize {
    let (mut best, mut run) = (0, 0);
    for c in s.chars() {
        run = if is_numeric_like(c) { run + 1 } else { 0 };
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
    "benjamin",
    "alexander",
    "jacob",
    "jackson",
    "sebastian",
    "evelyn",
    "scarlett",
    "lily",
    "ella",
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
    // Counted in any script (NFKC leaves Arabic-Indic digits as they are).
    if segment.chars().filter(|c| is_numeric_like(*c)).count() > MAX_INDEX_DIGITS {
        return true;
    }
    // Numeric characters outside ASCII are never part of a plain name.
    if segment
        .chars()
        .any(|c| c.is_numeric() && !c.is_ascii_digit())
    {
        return true;
    }
    // Percent-encoded bytes (`pdupont%40example%2Ecom`) and `%uXXXX`
    // escapes.
    if has_percent_escape(segment) {
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
    spans.extend(hash_spans(s));
    spans.extend(split_aws_key_ids(s));
    spans
}

/// Whether `s` holds a percent-encoded byte (`%` + 2 hex digits) or a
/// `%uXXXX` escape (`%u` / `%U` + 4 hex digits).
fn has_percent_escape(s: &str) -> bool {
    let b = s.as_bytes();
    b.windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit())
        || b.windows(6).any(|w| {
            w[0] == b'%'
                && w[1].eq_ignore_ascii_case(&b'u')
                && w[2..].iter().all(u8::is_ascii_hexdigit)
        })
}

/// Password-hash prefixes: from the prefix to the end of the following
/// `[./A-Za-z0-9$=,]` run (the hash, even when its `.`-separated tail
/// looks like path segments).
fn hash_spans(s: &str) -> Vec<Range<usize>> {
    const PREFIXES: [&str; 8] = [
        "$2a$", "$2b$", "$2x$", "$2y$", "$argon2", "$scrypt$", "$6$", "$5$",
    ];
    let is_hash_char =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '$' | '=' | ',');
    let mut out = Vec::new();
    for prefix in PREFIXES {
        for (start, _) in s.match_indices(prefix) {
            let rest = &s[start + prefix.len()..];
            let tail: usize = rest
                .chars()
                .take_while(|c| is_hash_char(*c))
                .map(char::len_utf8)
                .sum();
            out.push(start..start + prefix.len() + tail);
        }
    }
    out
}

/// AWS access key ids (`AKIA` / `ASIA` + 16 of `[A-Z0-9]`) split by
/// separators (`AKIA.IOSF.ODNN.7EXA.MPLE`): the shape is tested with `.`,
/// `_`, `-`, `/` and spaces removed.
fn split_aws_key_ids(s: &str) -> Vec<Range<usize>> {
    let kept: Vec<(usize, char)> = s
        .char_indices()
        .filter(|(_, c)| !matches!(c, '.' | '_' | '-' | '/' | ' '))
        .collect();
    let mut out = Vec::new();
    for k in 0..kept.len().saturating_sub(19) {
        let head: String = kept[k..k + 4].iter().map(|(_, c)| c).collect();
        if (head == "AKIA" || head == "ASIA")
            && kept[k + 4..k + 20]
                .iter()
                .all(|(_, c)| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            let (last, c) = kept[k + 19];
            out.push(kept[k].0..last + c.len_utf8());
        }
    }
    out
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
    let encoded = s.char_indices().filter(|(i, _)| {
        let at = |len: usize, form: &str| {
            s[*i..]
                .get(..len)
                .is_some_and(|x| x.eq_ignore_ascii_case(form))
        };
        at(3, "%40") || at(6, "%u0040")
    });
    let ats: Vec<usize> = s
        .match_indices('@')
        .map(|(i, _)| i)
        .chain(encoded.map(|(i, _)| i))
        .collect();
    for at in ats {
        let start = s[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_local_char(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let domain_len: usize = s[at + 1..]
            .chars()
            .take_while(|c| is_domain_char(*c) || *c == '%')
            .map(char::len_utf8)
            .sum();
        let full = start..at + 1 + domain_len;
        out.push(shortest_email(s, full));
    }
    out
}

/// Runs of digits (any script, [`is_numeric_like`]) separated by single `.`, `_`,
/// `-`, space or `+`, with more than [`MAX_INDEX_DIGITS`] digits in total: a
/// value split across segments (`0612.345678`, `ab4111_1111.1111.1111`).
fn split_digit_runs(s: &str) -> Vec<Range<usize>> {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let is_sep = |c: char| matches!(c, '.' | '_' | '-' | ' ' | '+');
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !is_numeric_like(chars[i].1) {
            i += 1;
            continue;
        }
        let start = chars[i].0;
        let mut end_idx = i;
        let mut digits = 0usize;
        let mut j = i;
        loop {
            if j < chars.len() && is_numeric_like(chars[j].1) {
                digits += 1;
                end_idx = j;
                j += 1;
            } else if j + 1 < chars.len() && is_sep(chars[j].1) && is_numeric_like(chars[j + 1].1) {
                j += 1;
            } else {
                break;
            }
        }
        if digits > MAX_INDEX_DIGITS {
            let (last, c) = chars[end_idx];
            out.push(start..last + c.len_utf8());
        }
        i = end_idx + 1;
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

/// Strips forbidden characters and applies NFKC, so that compatibility
/// forms read like their ASCII counterparts before any rule runs
/// (fullwidth `４１１１`, `＠`, `．`, `＿`, mathematical `𝟎`). Stripped again
/// after folding. `None` when the folded name exceeds [`MAX_INPUT_BYTES`].
fn fold(raw: &str) -> Option<String> {
    let folded: String = strip_forbidden(raw).nfkc().collect();
    let folded = strip_forbidden(&folded);
    (folded.len() <= MAX_INPUT_BYTES).then_some(folded)
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
    let Some(cleaned) = fold(raw) else {
        return NormalizedName::wildcard();
    };
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
    // Every key folded once (NFKC); `None` for indices. A key that cannot
    // be folded within the bound (NFKC expansion) makes the whole path `*`:
    // the joined path would exceed the bound anyway.
    let mut folded: Vec<Option<String>> = Vec::with_capacity(parts.len());
    for p in parts {
        folded.push(match p {
            PathPart::Key(k) => match fold(k) {
                Some(k) => Some(k),
                None => return NormalizedName::wildcard(),
            },
            PathPart::Index => None,
        });
    }
    // Pass 1: keys that are dynamic or values on their own.
    let keys: Vec<Option<String>> = folded
        .iter()
        .map(|k| {
            k.as_ref().and_then(|k| {
                let dynamic = k.chars().all(char::is_numeric)
                    || k.contains('.')
                    || segment_looks_like_value(k);
                (!dynamic).then(|| k.clone())
            })
        })
        .collect();
    // Pass 2: the whole path. Keys holding a dot or a percent-encoded byte,
    // and indices, are blanked with `#` (no detector reads `#`): a key such
    // as `jane.doe@example.com` is a complete value, and its local part must
    // not be read as extending over the previous keys.
    let mut joined = String::with_capacity(total);
    let mut ranges = Vec::with_capacity(parts.len());
    for (folded_key, key) in folded.iter().zip(&keys) {
        if !joined.is_empty() {
            joined.push('.');
        }
        let start = joined.len();
        match (folded_key, key) {
            (Some(_), Some(k)) => joined.push_str(k),
            (Some(k), None) if k.contains('.') || has_percent_escape(k) => {
                joined.push_str(&"#".repeat(k.len().max(1)));
            }
            (Some(k), None) => joined.push_str(k),
            (None, _) => joined.push('#'),
        }
        ranges.push(start..joined.len());
    }
    // NFKC may expand the keys beyond the raw bound: the detectors only
    // scan bounded input.
    if joined.len() > MAX_INPUT_BYTES {
        return NormalizedName::wildcard();
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
    // Bounded before folding, like `normalize_path`: NFKC never runs on an
    // oversized input.
    if raw.len() > MAX_INPUT_BYTES {
        return NormalizedName::wildcard();
    }
    let Some(cleaned) = fold(raw) else {
        return NormalizedName::wildcard();
    };
    if cleaned.contains('\\') || cleaned.contains('+') {
        return NormalizedName::wildcard();
    }
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
        // `#…` is a BER-encoded (hex) value: never kept.
        let bad = value.is_empty()
            || value.starts_with('#')
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

    /// Security review H1 / H2 / L1 / L2 / L3 regressions.
    #[test]
    fn review_bypasses_are_closed() {
        use PathPart::Key;
        for raw in [
            // H1: non-ASCII digits.
            "users.４１１１１１１１１１１１１１１１.x",
            "tel_٠٦١٢٣٤٥٦٧٨",
            "a.𝟎𝟔𝟏𝟐𝟑𝟒𝟓𝟔𝟕",
            "a.٠٦١٢",
            // H2: encoded addresses.
            "contacts.pdupont＠example．com.phone",
            "contacts.pdupont%40example%2Ecom.phone",
            // L1: bcrypt tail.
            "x.$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
            // L2: digits spread over the name, split AWS key id.
            "a.x061234.y5678",
            "AKIA.IOSF.ODNN.7EXA.MPLE",
            "keys_ASIA_IOSF_ODNN_7EXA_MPLE",
        ] {
            let out = normalize_path(raw);
            let out = out.as_str();
            assert!(
                !out.chars().any(char::is_numeric) && !out.contains("pdupont"),
                "{raw} -> {out}"
            );
            assert!(
                !out.contains("Ss7K") && !out.contains("MPLE"),
                "{raw} -> {out}"
            );
        }
        assert_eq!(
            normalize_path("contacts.pdupont＠example．com.phone").as_str(),
            "*.phone"
        );
        for parts in [
            vec![Key("by_tel"), Key("０６１２３４５６７８")],
            vec![
                Key("contacts"),
                Key("pdupont%40example%2Ecom"),
                Key("phone"),
            ],
            vec![Key("contacts"), Key("pdupont＠example．com"), Key("phone")],
        ] {
            let out = normalize_field_path(&parts);
            assert!(
                out.as_str() == "by_tel.*" || out.as_str() == "contacts.*.phone",
                "{parts:?} -> {out:?}"
            );
        }
        for (dn, want) in [
            ("ou=０６１２３４５６７８,dc=x", "ou=*,dc=x"),
            ("ou=pdupont%40example.com,dc=x", "ou=*,dc=x"),
            ("ou=#04024869,dc=x", "ou=*,dc=x"),
        ] {
            assert_eq!(normalize_ldap_dn(dn).as_str(), want, "{dn}");
        }
    }

    /// `U+FDFA` folds (NFKC) to 18 characters, 33 bytes, from 3 bytes.
    const EXPANDING: &str = "\u{FDFA}";

    #[test]
    fn unfoldable_field_path_key_is_a_wildcard_never_a_literal() {
        use PathPart::Key;
        // Re-review L1: one key over the bound once folded.
        let big = EXPANDING.repeat(1300);
        assert!(big.len() <= MAX_INPUT_BYTES);
        assert!(fold(&big).is_none());
        let out = normalize_field_path(&[Key("contacts"), Key(&big), Key("phone")]);
        assert_eq!(out.as_str(), "*");
        assert!(!out.as_str().contains('#'));
    }

    #[test]
    fn joined_field_path_is_bounded_after_folding() {
        use PathPart::Key;
        // Re-review L2: every key fits once folded, the joined path does not.
        let key = EXPANDING.repeat(10);
        assert!(fold(&key).is_some());
        let parts: Vec<PathPart<'_>> = (0..100).map(|_| Key(&key)).collect();
        let raw: usize = parts.len() * (key.len() + 1);
        assert!(raw <= MAX_INPUT_BYTES);
        assert_eq!(normalize_field_path(&parts).as_str(), "*");
        // Below the bound, the same shape is normalized as usual.
        assert_eq!(
            normalize_field_path(&[Key("a"), PathPart::Index, Key("b")]).as_str(),
            "a[].b"
        );
    }

    #[test]
    fn oversized_ldap_dn_is_refused_before_folding() {
        // Re-review L3: format characters stripped by folding would bring
        // it under the bound; the raw length decides first.
        let raw = format!("ou=people,dc=x{}", "\u{200B}".repeat(2000));
        assert!(raw.len() > MAX_INPUT_BYTES);
        assert!(fold(&raw).is_some());
        assert_eq!(normalize_ldap_dn(&raw).as_str(), "*");
        assert_eq!(
            normalize_ldap_dn("ou=people,dc=x\u{200B}").as_str(),
            "ou=people,dc=x"
        );
    }

    #[test]
    fn percent_u_escapes_are_values() {
        use PathPart::Key;
        // Re-review L4: `%uXXXX` like `%XX`, `%u0040` read as `@`.
        assert!(has_percent_escape("a%u0040b"));
        assert!(has_percent_escape("a%U00e9"));
        assert!(!has_percent_escape("a%u00"));
        assert!(!has_percent_escape("a%uzzzz"));
        for raw in [
            "contacts.pdupont%u0040example%u002Ecom.phone",
            "contacts.pdupont%U0040example.com",
            "x.name%u00e9",
        ] {
            let out = normalize_path(raw);
            assert!(!out.as_str().contains("pdupont"), "{raw} -> {out:?}");
            assert!(!out.as_str().contains('%'), "{raw} -> {out:?}");
        }
        // Read as an address (as `%40`): masked, conservatively to the end.
        assert_eq!(
            normalize_path("contacts.pdupont%u0040example%u002Ecom.phone").as_str(),
            normalize_path("contacts.pdupont%40example%2Ecom.phone").as_str()
        );
        assert_eq!(
            normalize_field_path(&[
                Key("contacts"),
                Key("pdupont%u0040example%u002Ecom"),
                Key("phone"),
            ])
            .as_str(),
            "contacts.*.phone"
        );
        assert_eq!(
            normalize_ldap_dn("ou=pdupont%u0040example.com,dc=x").as_str(),
            "ou=*,dc=x"
        );
        assert!(!address_spans("jdoe%u0040example.com").is_empty());
    }

    #[test]
    fn cjk_ideographic_digits_are_counted() {
        // Re-review L4: `零〇一二三四五六七八九` count as digits, and so do
        // the financial forms (review of the follow-ups, L3).
        for c in "零〇一二三四五六七八九壹贰叁肆伍陆柒捌玖貳參陸两兩拾".chars()
        {
            assert!(is_numeric_like(c), "{c}");
        }
        assert!(!is_numeric_like('日') && !is_numeric_like('a'));
        assert_eq!(longest_digit_run("tel_六一二三四五六七八"), 9);
        for raw in [
            "tel_六一二三四五六七八",
            "users.零六一二三四五六七八.phone",
            "a.x零六一二三四.y五六七八",
        ] {
            let out = normalize_path(raw);
            assert!(
                !out.as_str().chars().any(is_numeric_like),
                "{raw} -> {out:?}"
            );
        }
        // Gate: every segment below the per-segment bound, the total above
        // `MAX_TOTAL_DIGITS`.
        assert_eq!(
            NormalizedName::checked("ou=一二三四,dc=五六七八九".to_owned()).as_str(),
            "*"
        );
        assert_eq!(normalize_ldap_dn("ou=一二三四,dc=五六七八九").as_str(), "*");
        for raw in [
            "tel_陆壹贰叁肆伍陆柒捌",
            "acct.壹貳參肆伍陸柒捌玖",
            "a.x两拾壹贰叁肆.y伍陆柒捌",
        ] {
            let out = normalize_path(raw);
            assert!(
                !out.as_str().chars().any(is_numeric_like),
                "{raw} -> {out:?}"
            );
        }
        assert_eq!(normalize_path("tel_陆壹贰叁肆伍陆柒捌").as_str(), "*");
        // Hangul numerals are not counted (ordinary syllables).
        assert!(!is_numeric_like('일') && !is_numeric_like('삼'));
        assert_eq!(
            normalize_path("일이삼사오육칠팔").as_str(),
            "일이삼사오육칠팔"
        );
        // A few ideographic digits in an ordinary name are kept.
        assert_eq!(normalize_path("第一名").as_str(), "第一名");
        assert_eq!(normalize_path("sales.一月").as_str(), "sales.一月");
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
