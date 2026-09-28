//! Value detectors.
//!
//! Two kinds:
//! - **token detectors** find validated tokens anywhere in a value, so they
//!   also work on free text (`Customer called from 01 99 00 27 59`):
//!   e-mail, IBAN, card number, NIR, phone, AWS access key id (and a secret
//!   access key next to its key id or its name), password hash, and a date
//!   of birth introduced by its label (`born 17/05/1980`, `né le …`);
//! - **whole-value analyzers** recognize a value that is entirely a date, a
//!   person name, a postal address or an AWS secret access key. They are
//!   weak one value at a time: the column decides ([`crate::column`]) from
//!   the share of matching values, their distribution (age of dates), a
//!   lexicon of given names and surnames, and the column name when it
//!   gives a hint ([`crate::hints`]).
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
use zeroize::Zeroizing;

use crate::id::ClassifierId;
use crate::lexicon;
use crate::validate;

/// Bytes of a value examined by the detectors (cut on a char boundary).
pub const MAX_SCAN_BYTES: usize = 8 * 1024;
/// Most tokens reported for one value.
const MAX_TOKENS_PER_VALUE: usize = 64;
/// Longest whole value [`parse_date`] accepts (bytes).
const DATE_MAX_BYTES: usize = 64;
/// Bytes examined before an e-mail token for its context.
const EMAIL_PREFIX_BYTES: usize = 64;

/// A validated token found in a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Classifier that recognized the token.
    pub classifier: ClassifierId,
    /// Byte range in the scanned value.
    pub range: Range<usize>,
}

/// Compiles a detector pattern. Patterns are compile-time constants, so a
/// failure is a build defect (e.g. a `regex` crate feature missing from the
/// production feature set, like `unicode-case` for `(?i)`), never a data
/// condition. It must not disable a detector silently: the agent stops with
/// the pattern name (no value is involved). [`check_patterns`] forces every
/// pattern at startup; `tests/regex_features.rs` checks the production
/// feature set without dev-dependency feature unification.
#[allow(clippy::panic)] // a silently disabled detector would be worse
fn re(name: &str, pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => panic!("classifier pattern {name} does not compile: {e}"),
    }
}

static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "EMAIL",
        r"[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}\-]+(?:\.[\p{L}\p{N}\-]+)*\.\p{L}{2,}",
    )
});
static IBAN_START: LazyLock<Regex> = LazyLock::new(|| re("IBAN_START", r"(?i)\b[a-z]{2}[0-9]{2}"));
static CARD: LazyLock<Regex> = LazyLock::new(|| re("CARD", r"\b[0-9](?:[ \-]?[0-9]){11,22}\b"));
static NIR: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "NIR",
        concat!(
            r"\b[12](?:[ .\-]?[0-9]){4}[ .\-]?(?:[0-9][ .\-]?[0-9]|2[AaBb])",
            r"(?:[ .\-]?[0-9]){6}(?:[ .\-]|\s?/\s?|\s{2})?[0-9]{2}\b"
        ),
    )
});
/// International: `+` or `00`, country code, 8 to 15 digits in total; an
/// area code may be in parentheses, a trunk `(0)` is ignored.
static PHONE_INTL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_INTL",
        r"(?:\+|\b00)[1-9](?:[ .\-/]{0,2}(?:\(0\)|\([0-9]{1,4}\)|[0-9])){6,17}",
    )
});
/// North American: `(202) 555-0125`, `202-555-0125`, `1 202.555.0125`.
static PHONE_NANP: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_NANP",
        r"(?:\b1[ .\-]?)?(?:\([2-9][0-9]{2}\)[ .\-]?|\b[2-9][0-9]{2}[ .\-])[2-9][0-9]{2}[ .\-][0-9]{4}\b",
    )
});
/// Mobile numbers without a trunk prefix, in their national grouping:
/// Italian `347 123 4567`, Spanish `612 34 56 78`.
static PHONE_GROUPED: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_GROUPED",
        r"\b3[0-9]{2}[ .\-][0-9]{3}[ .\-][0-9]{4}\b|\b[6-9][0-9]{2}(?: [0-9]{2}){3}\b",
    )
});
/// National numbers with a trunk `0` (FR, UK, DE, IT, NL, BE, CH…):
/// `01 99 00 27 59`, `020 7946 0958`, `(030) 1234567`, `0612345678`.
static PHONE_TRUNK: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_TRUNK",
        r"(?:\(0[1-9][0-9]{0,4}\)|\b0[1-9][0-9]{0,4})(?:[ .\-/]?[0-9]+){1,5}",
    )
});
/// A phone label before a number in text.
static PHONE_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_LABEL",
        r"(?i)(?:\bt[ée]l\b|\bt[ée]l[ée]phone|phone|\bfax\b|mobile|portable|\bgsm\b|\bcell|\bcall|\bappel|joindre|whatsapp|\bsms\b|\bmob\b|telefon|\bn[°o]\s*(?:de\s+)?t[ée]l)[^0-9]{0,24}$",
    )
});
static PHONE_EXTENSION: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PHONE_EXTENSION",
        r"(?i)[\s,;]*(?:x|ext\.?|extn\.?|extension|poste|p\.|#)\s*[0-9]{1,6}\s*$",
    )
});
static AWS_ID: LazyLock<Regex> =
    LazyLock::new(|| re("AWS_ID", r"(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}"));
/// A secret access key introduced by its name (`aws_secret_access_key =`,
/// `"SecretAccessKey": "…"`).
static AWS_SECRET_CTX: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "AWS_SECRET_CTX",
        concat!(
            r#"(?i:secret[_\-. ]?(?:access[_\-. ]?)?key|aws[_\-. ]?secret|secretkey)"#,
            r#"["']?\s*(?::|=>?|\s)\s*["']?([A-Za-z0-9/+]{40})"#
        ),
    )
});
/// A secret access key right after its key id (`AKIA…:secret`, CSV).
static AWS_SECRET_AFTER_ID: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "AWS_SECRET_AFTER_ID",
        r#"^["']?[\s:,;|/=\t]{1,3}["']?([A-Za-z0-9/+]{40})"#,
    )
});
static PASSWORD_HASH: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "PASSWORD_HASH",
        concat!(
            r"(?:",
            // bcrypt (and Django's bcrypt wrappers)
            r"(?:bcrypt(?:_sha256)?\$)?\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}",
            // argon2 PHC (and Django's argon2 wrapper)
            r"|(?:argon2)?\$argon2(?:id|i|d)\$(?:v=[0-9]+\$)?m=[0-9]+,t=[0-9]+,p=[0-9]+(?:,[a-z]+=[A-Za-z0-9+/]+)*\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*",
            // scrypt PHC, crypt $7$, Werkzeug scrypt, yescrypt
            r"|\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/.]+=*\$[A-Za-z0-9+/.]+=*",
            r"|\$7\$[./A-Za-z0-9]{11,}\$[./A-Za-z0-9]{43}",
            r"|scrypt:[0-9]+:[0-9]+:[0-9]+\$[A-Za-z0-9./+]+\$[0-9a-f]{32,256}",
            r"|\$g?y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}",
            // crypt(3) SHA-256 / SHA-512 / MD5 / Apache MD5 / NetBSD SHA-1
            r"|\$5\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}",
            r"|\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}",
            r"|\$(?:1|apr1)\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}",
            r"|\$sha1\$[0-9]+\$[./A-Za-z0-9]{1,64}\$[./A-Za-z0-9]{28}",
            // phpass (WordPress, phpBB), Drupal 7
            r"|\$[PH]\$[./A-Za-z0-9]{31}",
            r"|\$S\$[./A-Za-z0-9]{52}",
            // pbkdf2: PHC / passlib, Django, Werkzeug
            r"|\$pbkdf2(?:-sha(?:1|256|512))?\$[0-9]+\$[./A-Za-z0-9+]+=*\$[./A-Za-z0-9+]+=*",
            r"|pbkdf2_sha(?:1|256|512)\$[0-9]+\$[^$\s]+\$[A-Za-z0-9+/]+=*",
            r"|pbkdf2:sha(?:1|256|512)(?::[0-9]+)?\$[^$\s]+\$[0-9a-f]{40,128}",
            // Django legacy salted digests
            r"|(?:sha1|md5|sha256)\$[A-Za-z0-9./+]{0,64}\$[0-9a-f]{32,64}",
            r"|unsalted_(?:md5|sha1)\$\$?[0-9a-f]{32,40}",
            // PostgreSQL SCRAM and md5, MySQL native and caching_sha2
            r"|SCRAM-SHA-(?:1|256)\$[0-9]+:[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*:[A-Za-z0-9+/]+=*",
            r"|md5[0-9a-f]{32}",
            r"|\*[0-9A-F]{40}",
            r"|\$A\$[0-9]{3}\$[!-~]{20}[./A-Za-z0-9]{43}",
            // LDAP / RFC 2307 schemes, Atlassian PKCS5S2
            r"|\{(?i:SSHA|SSHA256|SSHA384|SSHA512|SHA|SHA256|SHA384|SHA512|SMD5|MD5|CRYPT|PKCS5S2|BCRYPT|BLF-CRYPT|SHA256-CRYPT|SHA512-CRYPT|MD5-CRYPT|PBKDF2(?:-SHA(?:1|256|512))?|ARGON2)\}[A-Za-z0-9+/.$=,\-]{8,}",
            r")"
        ),
    )
});
/// Label introducing a date of birth in free text.
static BIRTH_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "BIRTH_LABEL",
        concat!(
            r"(?i)(?:\bborn(?:\s+on)?|\bdob\b|\bd\.o\.b\.?|date\s+of\s+birth|\bbirth\s*date|\bbirthday",
            r"|\bn[ée]e?(?:\(e\))?\s+le|date\s+de\s+naissance|\bddn\b|\bgeboren(?:\s+am)?|geburtsdatum",
            r"|fecha\s+de\s+nacimiento|nacid[oa]\s+el|nat[oa]\s+il|data\s+di\s+nascita)\s*[:\-=]?\s*"
        ),
    )
});

const TIME: &str = r"(?:[T\s]\s*(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(?:[AaPp]\.?[Mm]\.?)?\s*(?:Z|UTC|GMT|[+\-]\d{2}(?::?\d{2})?)?)?";

static ISO_DATE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "ISO_DATE",
        &format!(r"^(\d{{4}})([-/.])(\d{{1,2}})([-/.])(\d{{1,2}}){TIME}$"),
    )
});
static NUM_DATE: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "NUM_DATE",
        &format!(r"^(\d{{1,2}})([-/.])(\d{{1,2}})([-/.])(\d{{4}}){TIME}$"),
    )
});
static COMPACT_DATE: LazyLock<Regex> =
    LazyLock::new(|| re("COMPACT_DATE", r"^(\d{4})(\d{2})(\d{2})(?:T?000000)?$"));
static TEXT_DATE_DMY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "TEXT_DATE_DMY",
        &format!(
            r"^(?:(\p{{L}}+)[,.]?\s+)?(\d{{1,2}})(?:er|re|st|nd|rd|th|\.|º|°)?\s*(?:de\s+)?[\-/.\s]?\s*(\p{{L}}+)\.?[\-/.\s,]+(?:de\s+)?(\d{{4}}),?{TIME}$"
        ),
    )
});
static TEXT_DATE_MDY: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "TEXT_DATE_MDY",
        &format!(
            r"^(?:(\p{{L}}+)[,.]?\s+)?(\p{{L}}+)\.?[\s\-]+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+(\d{{4}}),?{TIME}$"
        ),
    )
});
static TEXT_DATE_YMD: LazyLock<Regex> = LazyLock::new(|| {
    re(
        "TEXT_DATE_YMD",
        r"^(\d{4})[\s\-/.](\p{L}+)\.?[\s\-/.](\d{1,2})$",
    )
});

/// Compiles every detector pattern now (they are otherwise compiled on
/// first use). Panics with the pattern name if one does not compile. The
/// agent calls it at startup (`core::runtime::run`), so a build defect
/// stops it before any scan instead of disabling a detector.
pub fn check_patterns() {
    for r in [
        &EMAIL,
        &IBAN_START,
        &CARD,
        &NIR,
        &PHONE_INTL,
        &PHONE_NANP,
        &PHONE_TRUNK,
        &PHONE_GROUPED,
        &PHONE_LABEL,
        &PHONE_EXTENSION,
        &AWS_ID,
        &AWS_SECRET_CTX,
        &AWS_SECRET_AFTER_ID,
        &PASSWORD_HASH,
        &BIRTH_LABEL,
        &ISO_DATE,
        &NUM_DATE,
        &COMPACT_DATE,
        &TEXT_DATE_DMY,
        &TEXT_DATE_MDY,
        &TEXT_DATE_YMD,
    ] {
        LazyLock::force(r);
    }
}

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

/// Per-value evidence besides the validated tokens: candidates that have
/// the shape of a checksummed identifier. A column where most candidates
/// fail the checksum holds other identifiers (order numbers, SIRETs…),
/// and the few that pass by chance are not reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Candidates {
    /// A 13–19 digit run (card-shaped), valid or not.
    pub card: bool,
    /// An IBAN-shaped run (country code, length), valid or not.
    pub iban: bool,
    /// A NIR-shaped run, valid or not.
    pub nir: bool,
    /// Strongest phone token of the value.
    pub phone: Option<PhoneStrength>,
}

/// Finds every validated token in a value. Tokens never overlap: detectors
/// run from the most to the least specific (AWS key id, password hash,
/// AWS secret key in context, e-mail, IBAN, card, NIR, labelled date of
/// birth, phone), so a phone-shaped group of digits inside an IBAN is not
/// reported as a phone. `enabled` restricts the classifiers (job filter).
#[must_use]
pub fn scan_tokens(value: &str, enabled: &dyn Fn(ClassifierId) -> bool) -> Vec<Token> {
    scan(value, enabled).0
}

/// [`scan_tokens`] plus the checksum candidates of the value.
pub(crate) fn scan(
    value: &str,
    enabled: &dyn Fn(ClassifierId) -> bool,
) -> (Vec<Token>, Candidates) {
    let v = bounded(value);
    let mut out = Vec::new();
    let mut cand = Candidates::default();
    // Every detector runs and claims its spans; the filter applies at the
    // end, so that a disabled IBAN detector does not turn IBAN digits into
    // phone numbers.
    aws_tokens(v, &mut out);
    {
        let r = &*PASSWORD_HASH;
        for m in r.find_iter(v) {
            if hash_boundaries(v, m.range()) {
                push(&mut out, ClassifierId::PasswordHash, m.range());
            }
        }
    }
    {
        let r = &*EMAIL;
        for m in r.find_iter(v) {
            if out.len() >= MAX_TOKENS_PER_VALUE {
                break;
            }
            let s = m.as_str().trim_end_matches(['.', '-']);
            let range = m.start()..m.start() + s.len();
            if validate::email_valid(s) && personal_email(v, range.clone()) {
                push(&mut out, ClassifierId::Email, range);
            }
        }
    }
    for (range, valid) in iban_tokens(v) {
        if overlaps(&out, &range) {
            continue;
        }
        cand.iban = true;
        if valid {
            push(&mut out, ClassifierId::Iban, range);
        }
    }
    {
        let r = &*CARD;
        for m in r.find_iter(v) {
            if overlaps(&out, &m.range()) {
                continue;
            }
            let digits: Zeroizing<String> =
                Zeroizing::new(m.as_str().chars().filter(char::is_ascii_digit).collect());
            let phone_like = prev_char(v, m.start()) == Some('+') || digits.starts_with("00");
            if phone_like || validate::nir_valid(&digits) {
                continue;
            }
            match card_token(v, m.range()) {
                Some(range) => {
                    cand.card = true;
                    push(&mut out, ClassifierId::CardNumber, range);
                }
                None if (13..=19).contains(&digits.len()) => cand.card = true,
                None => {}
            }
        }
    }
    {
        let r = &*NIR;
        for m in r.find_iter(v) {
            if overlaps(&out, &m.range()) || !isolated_number(v, m.range()) {
                continue;
            }
            cand.nir = true;
            let alnum: Zeroizing<String> = Zeroizing::new(
                m.as_str()
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .map(|c| c.to_ascii_uppercase())
                    .collect(),
            );
            if validate::nir_valid(&alnum) {
                push(&mut out, ClassifierId::Nir, m.range());
            }
        }
    }
    birth_date_tokens(v, &mut out);
    cand.phone = phone_tokens(v, &mut out);
    out.retain(|t| enabled(t.classifier));
    out.sort_by_key(|t| t.range.start);
    (out, cand)
}

/// AWS access key ids, and secret access keys introduced by their name or
/// following a key id.
fn aws_tokens(v: &str, out: &mut Vec<Token>) {
    let not_key_char = |c: Option<char>| c.is_none_or(|c| !c.is_ascii_alphanumeric());
    let mut ids = Vec::new();
    {
        let r = &*AWS_ID;
        for m in r.find_iter(v) {
            if not_key_char(prev_char(v, m.start())) && not_key_char(next_char(v, m.end())) {
                ids.push(m.range());
                push(out, ClassifierId::AwsKey, m.range());
            }
        }
    }
    let secret_end = |end: usize| {
        next_char(v, end)
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '=')))
    };
    {
        let r = &*AWS_SECRET_AFTER_ID;
        for id in ids {
            if let Some(g) = r.captures(&v[id.end..]).and_then(|c| c.get(1)) {
                let range = id.end + g.start()..id.end + g.end();
                if secret_end(range.end) && is_aws_secret_key(&v[range.clone()]) {
                    push(out, ClassifierId::AwsKey, range);
                }
            }
        }
    }
    {
        let r = &*AWS_SECRET_CTX;
        for c in r.captures_iter(v) {
            if let Some(g) = c.get(1)
                && secret_end(g.end())
                && is_aws_secret_key(g.as_str())
            {
                push(out, ClassifierId::AwsKey, g.range());
            }
        }
    }
}

/// A password hash is a whole token: not glued to other hash characters.
fn hash_boundaries(v: &str, r: Range<usize>) -> bool {
    let before = prev_char(v, r.start).is_none_or(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '$' | '.' | '/' | '+' | '*' | '_'))
    });
    let after = next_char(v, r.end).is_none_or(|c| {
        !(c.is_ascii_alphanumeric() || matches!(c, '$' | '.' | '/' | '+' | '=' | '_'))
    });
    before && after
}

/// Local parts of system and placeholder mailboxes: not a person's address.
const SYSTEM_LOCAL_PARTS: &[&str] = &[
    "noreply",
    "no-reply",
    "no_reply",
    "donotreply",
    "do-not-reply",
    "do_not_reply",
    "dontreply",
    "mailer-daemon",
    "mailerdaemon",
    "postmaster",
    "hostmaster",
    "webmaster",
    "abuse",
    "root",
    "daemon",
    "nobody",
    "bounce",
    "bounces",
    "git",
    "www-data",
    "notifications",
    "notification",
    "notify",
    "alerts",
    "alert",
    "system",
    "devnull",
    "null",
    "automated",
    "autoreply",
    "auto-reply",
    "robot",
    "bot",
    "cron",
    "jenkins",
    "builds",
    "deploy",
    "deployer",
    "ubuntu",
    "ec2-user",
    "centos",
    "user",
    "username",
    "test",
    "testing",
    "tester",
    "email",
    "e-mail",
    "mail",
    "name",
    "someone",
    "somebody",
    "anyone",
    "you",
    "your",
    "yourname",
    "your.name",
    "youremail",
    "your.email",
    "yourmail",
    "foo",
    "bar",
    "foobar",
    "example",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "changeme",
    "xxx",
    "xxxx",
    "abc",
    "none",
    "anonymous",
    "unknown",
    "invalid",
    "nomail",
    "noemail",
    "no-email",
    "firstname.lastname",
    "first.last",
    "prenom.nom",
    "nom.prenom",
];

/// Top-level domains that are not public mail domains, and file
/// extensions (`icon@2x.png`).
const NON_MAIL_TLDS: &[&str] = &[
    "local",
    "localhost",
    "localdomain",
    "internal",
    "intranet",
    "lan",
    "invalid",
    "arpa",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "bmp",
    "ico",
    "tif",
    "tiff",
    "js",
    "css",
    "html",
    "htm",
    "json",
    "xml",
    "txt",
    "pdf",
    "csv",
    "log",
    "yaml",
    "yml",
    "tmp",
    "bak",
    "gz",
    "tar",
    "exe",
    "dll",
    "jar",
    "rb",
    "java",
    "ts",
    "tsx",
    "jsx",
    "lock",
    "toml",
    "ini",
    "cfg",
    "conf",
    "mp3",
    "mp4",
    "wav",
    "avi",
    "mov",
    "docx",
    "xlsx",
    "pptx",
];

/// Whether an e-mail-shaped token is a person's mailbox: not the user
/// part of a URI (`https://user@host/`, `ssh://git@host`), not an scp-like
/// remote (`git@github.com:org/repo`), not glued to other text (message
/// ids, `key=value` blobs), not a machine-generated or system / placeholder
/// local part (`noreply`, `mailer-daemon`, UUIDs), not a local or file
/// "domain" (`host.local`, `icon@2x.png`).
fn personal_email(v: &str, r: Range<usize>) -> bool {
    let token = &v[r.clone()];
    let Some((local, domain)) = token.rsplit_once('@') else {
        return false;
    };
    // What precedes the token in the same whitespace-delimited word, at
    // most `EMAIL_PREFIX_BYTES` back (constant work per token).
    let mut window = r.start.saturating_sub(EMAIL_PREFIX_BYTES);
    while !v.is_char_boundary(window) {
        window += 1;
    }
    let word_start = v[window..r.start]
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map_or(window, |(i, c)| window + i + c.len_utf8());
    let prefix = &v[word_start..r.start];
    let mailto = prefix
        .len()
        .checked_sub(7)
        .and_then(|i| prefix.as_bytes().get(i..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(b"mailto:"));
    if prefix.contains("//") {
        return false;
    }
    let prefix_ok = match prefix.chars().next_back() {
        None => true,
        Some('<' | '(' | '[' | '{' | '"' | '\'' | ',' | ';' | '>' | '|' | '«') => {
            !prefix.contains('/')
        }
        Some(':') => {
            mailto
                || prefix[..prefix.len() - 1]
                    .chars()
                    .all(|c| c.is_alphabetic() || matches!(c, '-' | '_' | '"' | '\''))
        }
        Some('=') => prefix[..prefix.len() - 1]
            .chars()
            .rev()
            .take_while(|c| !matches!(c, '&' | '?' | ';' | ','))
            .all(|c| c.is_ascii_alphabetic() || c == '_' || c == '-'),
        Some(_) => false,
    };
    if !prefix_ok {
        return false;
    }
    let after = &v[r.end..];
    let mut next = after.chars();
    let suffix_ok = match next.next() {
        None => true,
        Some(c) if c.is_whitespace() => true,
        Some('>' | ')' | ']' | '}' | '"' | '\'' | ',' | ';' | '!' | '?' | '|' | '»' | '&') => true,
        Some('.' | ':') => next.next().is_none_or(char::is_whitespace),
        Some(_) => false,
    };
    if !suffix_ok {
        return false;
    }
    let lower_local = Zeroizing::new(local.to_lowercase());
    let base = lower_local.split('+').next().unwrap_or("");
    if SYSTEM_LOCAL_PARTS.contains(&base)
        || [
            "noreply",
            "no-reply",
            "donotreply",
            "do-not-reply",
            "mailer-daemon",
            "bounce",
        ]
        .iter()
        .any(|s| lower_local.contains(s))
    {
        return false;
    }
    let lower_domain = Zeroizing::new(domain.to_lowercase());
    if lower_domain.contains("noreply") || lower_domain.contains("no-reply") {
        return false;
    }
    let labels: Vec<&str> = lower_domain.split('.').collect();
    let tld = labels.last().copied().unwrap_or("");
    if NON_MAIL_TLDS.contains(&tld) {
        return false;
    }
    if labels.first().is_some_and(|l| {
        l.len() >= 2 && l.ends_with('x') && l[..l.len() - 1].bytes().all(|b| b.is_ascii_digit())
    }) {
        return false;
    }
    let bracketed = prefix.ends_with('<') && after.starts_with('>');
    !machine_local_part(local, bracketed)
}

/// Machine-generated local parts: message ids, UUIDs, hashes, bounce and
/// reply tokens.
fn machine_local_part(local: &str, bracketed: bool) -> bool {
    let digits = local.chars().filter(char::is_ascii_digit).count();
    if local.chars().count() > 40 || digits >= 10 {
        return true;
    }
    if bracketed && (digits >= 4 || local.len() >= 20) {
        return true;
    }
    // Hex runs (UUIDs, hashes), separators ignored.
    let mut run = 0;
    let (mut run_digits, mut run_letters) = (0, 0);
    for c in local.chars().filter(|c| !matches!(c, '-' | '.' | '_')) {
        if c.is_ascii_hexdigit() {
            run += 1;
            if c.is_ascii_digit() {
                run_digits += 1;
            } else {
                run_letters += 1;
            }
            if run >= 12 && run_digits >= 3 && run_letters >= 2 {
                return true;
            }
        } else {
            run = 0;
            run_digits = 0;
            run_letters = 0;
        }
    }
    // Random mixed-case segments with digits (`E1rX9Kp-0003Qx`): many
    // switches between upper case, lower case and digits.
    let class = |c: &char| {
        if c.is_ascii_digit() {
            0
        } else if c.is_uppercase() {
            1
        } else {
            2
        }
    };
    local.split(['.', '-', '_', '+', '=']).any(|seg| {
        let classes: Vec<u8> = seg.chars().map(|c| class(&c)).collect();
        let switches = classes.windows(2).filter(|w| w[0] != w[1]).count();
        switches >= 4 && classes.contains(&0) && classes.contains(&1)
    })
}

/// Removes spaces, dots and hyphens.
#[must_use]
pub fn compact(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-'))
        .collect()
}

/// A run of digits (with separators) not glued to more digits: the
/// character before / after is not a digit, even across one separator.
fn isolated_number(v: &str, r: Range<usize>) -> bool {
    let sep = |c: char| matches!(c, ' ' | '.' | '-' | '/');
    let before = &v[..r.start];
    let mut b = before.chars().rev();
    let ok_before = match b.next() {
        None => true,
        Some(c) if c.is_ascii_alphanumeric() => false,
        Some(c) if sep(c) => b.next().is_none_or(|c| !c.is_ascii_digit()),
        Some(_) => true,
    };
    let mut a = v[r.end..].chars();
    let ok_after = match a.next() {
        None => true,
        Some(c) if c.is_ascii_alphanumeric() => false,
        Some(c) if sep(c) => a.next().is_none_or(|c| !c.is_ascii_digit()),
        Some(_) => true,
    };
    ok_before && ok_after
}

/// IBAN-shaped runs: `CCkk` at a word start (any case), then alphanumerics
/// with single separators (space, hyphen, dot), exactly the country
/// length, ending at a token boundary. Returns each run and whether it
/// passes the checksum.
fn iban_tokens(v: &str) -> Vec<(Range<usize>, bool)> {
    let start_re = &*IBAN_START;
    let mut out = Vec::new();
    for m in start_re.find_iter(v) {
        let Some(len) = validate::iban_length(&m.as_str()[..2].to_ascii_uppercase()) else {
            continue;
        };
        let mut compact = Zeroizing::new(String::with_capacity(len));
        let mut end = m.start();
        let mut last_sep = false;
        for (i, c) in v[m.start()..].char_indices() {
            if compact.len() == len {
                break;
            }
            if matches!(c, ' ' | '-' | '.' | '\u{a0}') && !last_sep && !compact.is_empty() {
                last_sep = true;
                continue;
            }
            if c.is_ascii_alphanumeric() {
                compact.push(c.to_ascii_uppercase());
                last_sep = false;
                end = m.start() + i + c.len_utf8();
            } else {
                break;
            }
        }
        let boundary = next_char(v, end).is_none_or(|c| !c.is_alphanumeric());
        if compact.len() == len && boundary {
            out.push((m.start()..end, validate::iban_valid(&compact)));
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
        let digits: Zeroizing<String> =
            Zeroizing::new(s[..end].chars().filter(char::is_ascii_digit).collect());
        if (13..=19).contains(&digits.len())
            && validate::luhn_valid(&digits)
            && validate::card_prefix_valid(&digits)
        {
            return Some(range.start..range.start + end);
        }
    }
    None
}

/// Dates of birth introduced by a label (`born 17/05/1980`, `DOB: …`,
/// `née le 3 mars 1975`).
fn birth_date_tokens(v: &str, out: &mut Vec<Token>) {
    for m in BIRTH_LABEL.find_iter(v) {
        if out.len() >= MAX_TOKENS_PER_VALUE {
            break;
        }
        // The date is at most `DATE_MAX_BYTES` long (the `parse_date`
        // bound): only that window after the label is examined, so the
        // work per label is constant.
        let mut end = (m.end() + DATE_MAX_BYTES + 8).min(v.len());
        while !v.is_char_boundary(end) {
            end -= 1;
        }
        let rest = &v[m.end()..end];
        // One to five words; try the longest first.
        let mut ends: Vec<usize> = rest
            .char_indices()
            .filter(|(_, c)| c.is_whitespace())
            .map(|(i, _)| i)
            .take(5)
            .collect();
        ends.push(rest.len());
        ends.truncate(5);
        for end in ends.into_iter().rev() {
            let cand = rest[..end].trim_end_matches(['.', ',', ';', ')', ':']);
            if !cand.is_empty() && is_birth_date(cand) {
                let start = m.end();
                push(out, ClassifierId::BirthDate, start..start + cand.len());
                break;
            }
        }
    }
}

/// How much a phone token looks like a phone number on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PhoneStrength {
    /// Compact national digits (`0612345678`): also zero-padded
    /// identifiers; counts only under a phone name.
    Weak,
    /// A national format with consistent separators that fits a numbering
    /// plan (`01 99 00 27 59`, `020 7946 0958`, `202-555-0125`).
    Normal,
    /// `+` and a country code, an area code in parentheses, or a phone
    /// label just before (`tel`, `phone`, `call`, `appeler`…).
    Strong,
}

/// Phone tokens: international, North American, national with a trunk `0`,
/// Italian / Spanish mobile groupings. Returns the strongest strength seen.
fn phone_tokens(v: &str, out: &mut Vec<Token>) -> Option<PhoneStrength> {
    let mut best: Option<PhoneStrength> = None;
    for (kind, r) in [
        (0, &*PHONE_INTL),
        (1, &*PHONE_NANP),
        (2, &*PHONE_TRUNK),
        (3, &*PHONE_GROUPED),
    ] {
        for m in r.find_iter(v) {
            let text = m.as_str();
            let before = prev_char(v, m.start());
            if before.is_some_and(|c| {
                c.is_alphanumeric() || matches!(c, '+' | '_' | '/' | '=' | '$' | '#' | '-' | '.')
            }) {
                continue;
            }
            // Not the end of a longer number either (`… 3704 0044 0532`).
            let mut back = v[..m.start()].chars().rev();
            if back.next().is_some_and(|c| matches!(c, ' ' | '.' | '-'))
                && back.next().is_some_and(|c| c.is_ascii_digit())
            {
                continue;
            }
            // Not the start of a longer number or code, a time, a decimal
            // or a word.
            let mut after = v[m.end()..].chars();
            let glued = match after.next() {
                None => false,
                Some(c) if c.is_alphanumeric() || matches!(c, ':' | '_' | '@' | '%') => true,
                Some(' ' | ',') => after.next().is_some_and(|c| c.is_ascii_digit()),
                Some('.' | '-' | '/') => after.next().is_some_and(|c| c.is_ascii_alphanumeric()),
                Some(_) => false,
            };
            if glued {
                continue;
            }
            // Digits, without the `0` of a trunk `(0)` (no copy).
            let digits: usize =
                text.chars().filter(char::is_ascii_digit).count() - text.matches("(0)").count();
            let separated = text.chars().any(|c| !c.is_ascii_digit() && c != '+');
            let strength = match kind {
                // `+` / `00` prefix: 8 to 15 digits after it; `00` needs
                // separators (zero-padded identifiers are not phones).
                0 => {
                    let plus = text.starts_with('+');
                    let n = if plus {
                        digits
                    } else {
                        digits.saturating_sub(2)
                    };
                    ((8..=15).contains(&n) && (plus || separated)).then_some(if plus {
                        PhoneStrength::Strong
                    } else {
                        PhoneStrength::Normal
                    })
                }
                1 => nanp_valid(text).then_some(if text.contains('(') {
                    PhoneStrength::Strong
                } else {
                    PhoneStrength::Normal
                }),
                2 => {
                    let ok_len = if separated {
                        (9..=12).contains(&digits)
                    } else {
                        (10..=11).contains(&digits)
                    };
                    (ok_len && !date_shaped(text)).then(|| trunk_strength(text))
                }
                _ => consistent_separators(text).then_some(PhoneStrength::Normal),
            };
            let Some(mut strength) = strength else {
                continue;
            };
            if phone_label_before(v, m.start()) {
                strength = PhoneStrength::Strong;
            }
            let before_len = out.len();
            push(out, ClassifierId::Phone, m.range());
            if out.len() > before_len {
                best = best.max(Some(strength));
            }
        }
    }
    best
}

/// A phone label in the few characters before a token.
fn phone_label_before(v: &str, start: usize) -> bool {
    let mut from = start.saturating_sub(32);
    while !v.is_char_boundary(from) {
        from += 1;
    }
    PHONE_LABEL.is_match(&v[from..start])
}

/// Only one kind of separator between digit groups (parentheses aside).
fn consistent_separators(text: &str) -> bool {
    let mut seps: Vec<char> = text
        .chars()
        .filter(|c| !c.is_ascii_digit() && !matches!(c, '(' | ')' | '+'))
        .collect();
    seps.dedup();
    seps.sort_unstable();
    seps.dedup();
    seps.len() <= 1
}

/// North American numbering plan: area code and exchange `[2-9]XX`, not
/// `N11`.
fn nanp_valid(text: &str) -> bool {
    let d: Vec<u8> = text.bytes().filter(u8::is_ascii_digit).collect();
    let d = if d.len() == 11 { &d[1..] } else { &d[..] };
    if d.len() != 10 {
        return false;
    }
    let n11 = |x: &[u8]| x[1] == b'1' && x[2] == b'1';
    // `(202) 555-0125`: the separators after the area code must agree.
    let rest = text.rsplit_once(')').map_or(text, |(_, r)| r.trim_start());
    !n11(&d[0..3]) && !n11(&d[3..6]) && consistent_separators(rest)
}

/// Strength of a national number with a trunk `0`: compact digits are weak;
/// separated digits are normal when the separators are consistent and the
/// groups fit a national numbering plan (below); an area code in
/// parentheses is strong.
fn trunk_strength(text: &str) -> PhoneStrength {
    let groups: Vec<usize> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .map(str::len)
        .collect();
    if groups.len() < 2 {
        return PhoneStrength::Weak;
    }
    if text.starts_with('(') {
        return PhoneStrength::Strong;
    }
    // Groupings of national plans after the trunk + area code: pairs
    // (FR `01 99 00 27 59`), 3-2-2 (CH, BE), 2-2-2 (BE mobiles), one
    // subscriber group of 6 to 8 digits (DE, NL, IT, UK `07700 900123`),
    // or two groups ending with 4 digits (UK `020 7946 0958`, IT
    // `06 1234 5678`). Identifier layouts (`0123-456-789`) do not fit.
    let tail = &groups[1..];
    let plan = (2..=5).contains(&groups[0])
        && (matches!(tail, [2, 2, 2, 2] | [2, 2, 2] | [3, 2, 2])
            || (matches!(tail, [6..=8]) && (groups[0] <= 4 || !text.contains('-')))
            || matches!(tail, [3 | 4, 4]));
    if plan && consistent_separators(text) {
        PhoneStrength::Normal
    } else {
        PhoneStrength::Weak
    }
}

/// Digit groups shaped like a date (`03.05.2024`, `2024-05-03`).
fn date_shaped(text: &str) -> bool {
    let groups: Vec<usize> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|g| !g.is_empty())
        .map(str::len)
        .collect();
    matches!(
        groups.as_slice(),
        [1 | 2, 1 | 2, 4, ..] | [4, 1 | 2, 1 | 2, ..]
    )
}

/// A whole value that is a phone number in a loose national format
/// (`347 123 4567`, `912 345 678`, `(0)30 1234 567 x12`): 7 to 15 digits
/// with the usual separators, an optional extension. Only used when the
/// column name designates phone numbers. Returns the range of the number
/// (without the extension).
#[must_use]
pub(crate) fn phone_loose(value: &str) -> Option<Range<usize>> {
    let start = value.len() - value.trim_start().len();
    let mut v = value.trim();
    if let Some(m) = PHONE_EXTENSION.find(v) {
        v = &v[..m.start()];
    }
    let v = v.trim_end();
    if v.is_empty()
        || !v
            .chars()
            .all(|c| c.is_ascii_digit() || " +().-/".contains(c))
    {
        return None;
    }
    if v[1..].contains('+') || date_shaped(v) {
        return None;
    }
    let digits = v.chars().filter(char::is_ascii_digit).count();
    (7..=15).contains(&digits).then_some(start..start + v.len())
}

/// Time of day attached to a date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeOfDay {
    /// Date only.
    None,
    /// A whole hour (`00:00:00`, or a midnight shifted by a time zone).
    WholeHour,
    /// Any other time: an event timestamp rather than a date.
    Other,
}

/// A calendar date parsed from a whole value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DateParts {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub time: TimeOfDay,
}

fn time_of_day(
    h: Option<&str>,
    m: Option<&str>,
    s: Option<&str>,
    f: Option<&str>,
) -> Option<TimeOfDay> {
    let Some(h) = h else {
        return Some(TimeOfDay::None);
    };
    let n = |x: Option<&str>| x.map_or(Some(0), |x| x.parse::<u32>().ok());
    let (h, m, s) = (h.parse::<u32>().ok()?, n(m)?, n(s)?);
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    let frac_zero = f.is_none_or(|f| f.bytes().all(|b| b == b'0'));
    Some(if m == 0 && s == 0 && frac_zero {
        TimeOfDay::WholeHour
    } else {
        TimeOfDay::Other
    })
}

fn grp<'h>(c: &regex::Captures<'h>, i: usize) -> Option<&'h str> {
    c.get(i).map(|m| m.as_str())
}

/// Parses a whole value as a calendar date: ISO (`-`, `/`, `.`),
/// `DD/MM/YYYY`, `MM/DD/YYYY` (day first unless impossible), `DD.MM.YYYY`,
/// `DD-MM-YYYY`, `YYYYMMDD`, textual months in EN / FR / DE / ES / IT / NL
/// / PT (`17 mai 1980`, `May 17, 1980`, `17-May-1980`), with an optional
/// time and zone. Checks the calendar and the 1900–2030 range.
#[must_use]
pub(crate) fn parse_date(value: &str) -> Option<DateParts> {
    let v = value.trim();
    if v.len() < 6 || v.len() > DATE_MAX_BYTES {
        return None;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let mk = |y: u32, m: u32, d: u32, t: TimeOfDay| {
        validate::birth_date_valid(y, m, d).then_some(DateParts {
            year: y,
            month: m,
            day: d,
            time: t,
        })
    };
    let g = grp;
    if let Some(c) = ISO_DATE.captures(v) {
        if g(&c, 2) != g(&c, 4) {
            return None;
        }
        let t = time_of_day(g(&c, 6), g(&c, 7), g(&c, 8), g(&c, 9))?;
        return mk(num(&c[1])?, num(&c[3])?, num(&c[5])?, t);
    }
    if let Some(c) = NUM_DATE.captures(v) {
        if g(&c, 2) != g(&c, 4) {
            return None;
        }
        let t = time_of_day(g(&c, 6), g(&c, 7), g(&c, 8), g(&c, 9))?;
        let (a, b, y) = (num(&c[1])?, num(&c[3])?, num(&c[5])?);
        // Day first unless impossible (`05/17/1980` is month first).
        return mk(y, b, a, t).or_else(|| mk(y, a, b, t));
    }
    if let Some(c) = COMPACT_DATE.captures(v) {
        return mk(num(&c[1])?, num(&c[2])?, num(&c[3])?, TimeOfDay::None);
    }
    let weekday_ok =
        |w: Option<&str>| w.is_none_or(|w| lexicon::WEEKDAYS.contains(&lexicon::fold(w).as_str()));
    if let Some(c) = TEXT_DATE_DMY.captures(v)
        && weekday_ok(g(&c, 1))
        && let Some(m) = lexicon::month(&lexicon::fold(&c[3]))
    {
        let t = time_of_day(g(&c, 5), g(&c, 6), g(&c, 7), g(&c, 8))?;
        return mk(num(&c[4])?, m, num(&c[2])?, t);
    }
    if let Some(c) = TEXT_DATE_MDY.captures(v)
        && weekday_ok(g(&c, 1))
        && let Some(m) = lexicon::month(&lexicon::fold(&c[2]))
    {
        let t = time_of_day(g(&c, 5), g(&c, 6), g(&c, 7), g(&c, 8))?;
        return mk(num(&c[4])?, m, num(&c[3])?, t);
    }
    if let Some(c) = TEXT_DATE_YMD.captures(v)
        && let Some(m) = lexicon::month(&lexicon::fold(&c[2]))
    {
        return mk(num(&c[1])?, m, num(&c[3])?, TimeOfDay::None);
    }
    None
}

/// A whole value that is a plausible date of birth: a real calendar date in
/// 1900–2030, in one of the formats of [`parse_date`], without a time of
/// day other than a whole hour (midnight, possibly shifted by a time zone).
#[must_use]
pub fn is_birth_date(value: &str) -> bool {
    parse_date(value).is_some_and(|d| d.time != TimeOfDay::Other)
}

/// What a whole value tells about a person name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct NameEvidence {
    /// A word is a common given name.
    pub given: bool,
    /// A word is a common surname.
    pub surname: bool,
    /// A word ends like a surname (`-sson`, `-ski`, `-escu`…).
    pub suffix: bool,
    /// Number of name words (titles, particles and initials excluded).
    pub words: usize,
}

impl NameEvidence {
    /// Whether the lexicon recognizes a word.
    pub(crate) fn known(&self) -> bool {
        self.given || self.surname || self.suffix
    }
}

#[derive(PartialEq)]
enum Case {
    Cap,
    Upper,
    Lower,
}

/// Case pattern of one letter-only name part (`Anaïs`, `DUPONT`,
/// `McDonald`, `dupont`); `None` otherwise.
fn name_part_case(p: &str) -> Option<Case> {
    let chars: Vec<char> = p.chars().collect();
    let first = *chars.first()?;
    if !chars.iter().all(|c| c.is_alphabetic()) {
        return None;
    }
    let rest = &chars[1..];
    if first.is_uppercase() {
        if rest.iter().all(|c| c.is_lowercase()) {
            return Some(Case::Cap);
        }
        if chars.len() >= 2 && rest.iter().all(|c| c.is_uppercase()) {
            return Some(Case::Upper);
        }
        // `McDonald`, `MacArthur`, `DiCaprio`, `LeBlanc`: one inner capital
        // after at least one lowercase letter, followed by lowercase.
        let inner: Vec<usize> = rest
            .iter()
            .enumerate()
            .filter(|(_, c)| c.is_uppercase())
            .map(|(i, _)| i)
            .collect();
        if let [i] = inner.as_slice()
            && *i >= 1
            && rest[..*i].iter().all(|c| c.is_lowercase())
            && rest.len() > i + 1
            && rest[i + 1..].iter().all(|c| c.is_lowercase())
        {
            return Some(Case::Cap);
        }
        return None;
    }
    chars
        .iter()
        .all(|c| c.is_lowercase())
        .then_some(Case::Lower)
}

/// Analyzes a whole value as a person name: 1 to 5 name words (given
/// names, surnames, compound `Jean-Pierre`, `O'Connor`, `McDonald`), in
/// capitalized, upper or lower case, lowercase particles (`de la`, `van
/// der`), initials (`J.`), leading titles (`Mr`, `Mme`, `Dr`), trailing
/// suffixes (`Jr.`), `LAST, First`. No digit, no other punctuation, no word
/// that marks an organization, a place, a product or a role. A lowercase
/// word must be a known given name or surname.
#[must_use]
pub(crate) fn name_evidence(value: &str) -> Option<NameEvidence> {
    let v = value.trim();
    let n = v.chars().count();
    if !(2..=70).contains(&n)
        || !v
            .chars()
            .all(|c| c.is_alphabetic() || matches!(c, ' ' | '-' | '\'' | '’' | '.' | ','))
        || v.matches(',').count() > 1
    {
        return None;
    }
    let mut words: Vec<&str> = v.split([' ', ',']).filter(|w| !w.is_empty()).collect();
    let bare = |w: &str| lexicon::fold(w.trim_end_matches('.'));
    while words.len() > 1 && lexicon::TITLES.contains(&bare(words[0]).as_str()) {
        words.remove(0);
    }
    while words.len() > 1
        && words
            .last()
            .is_some_and(|w| lexicon::NAME_SUFFIXES.contains(&bare(w).as_str()))
    {
        words.pop();
    }
    if words.len() > 7 {
        return None;
    }
    let mut ev = NameEvidence::default();
    for w in &words {
        if words.len() > 1 && lexicon::PARTICLES.contains(w) {
            continue;
        }
        // Initials: `J.`, `J`, `J.-P.`.
        let letters: Vec<char> = w.chars().filter(|c| c.is_alphabetic()).collect();
        if words.len() > 1
            && !letters.is_empty()
            && letters.iter().all(|c| c.is_uppercase())
            && w.split('-')
                .all(|p| p.trim_end_matches('.').chars().count() == 1)
        {
            continue;
        }
        if w.contains('.') {
            return None;
        }
        let mut lower = false;
        for part in w.split('-') {
            // Elided particle: `d'Angelo`, `O'Connor`, `l'Hermite`.
            let core = match part.find(['\'', '’']) {
                Some(i) if (1..=2).contains(&i) => {
                    let q = part[i..].chars().next().map_or(1, char::len_utf8);
                    &part[i + q..]
                }
                Some(_) => return None,
                None => part,
            };
            match name_part_case(core)? {
                Case::Lower => lower = true,
                Case::Cap | Case::Upper => {}
            }
        }
        let f = lexicon::fold(w);
        if lexicon::is_not_name_word(&f) || f.split('-').any(lexicon::is_not_name_word) {
            return None;
        }
        let parts: Vec<&str> = f.split('-').collect();
        let given = lexicon::is_given_name(&f) || parts.iter().all(|p| lexicon::is_given_name(p));
        let surname = lexicon::is_surname(&f)
            || lexicon::is_surname(&Zeroizing::new(f.replace('-', "")))
            || parts.iter().any(|p| lexicon::is_surname(p));
        let suffix = parts.iter().any(|p| lexicon::has_surname_suffix(p));
        if lower && !(given || surname) {
            return None;
        }
        // Street types (`Place Victor Hugo`, `Via Roma`) unless also a name.
        if f.len() >= 3 && !(given || surname) && (street_first(&f) || street_last(&f)) {
            return None;
        }
        ev.given |= given;
        ev.surname |= surname;
        ev.suffix |= suffix;
        ev.words += 1;
    }
    (1..=5).contains(&ev.words).then_some(ev)
}

/// A whole value shaped like a person name ([`name_evidence`]): 1 to 5
/// capitalized or all-caps words (lowercase only for known names),
/// letters with internal `-` / `'`, particles, initials, titles,
/// `LAST, First`. No digits, no `@`, no organization / place / product
/// word. Weak alone: the column decides with the lexicon and the name.
#[must_use]
pub fn is_person_name(value: &str) -> bool {
    name_evidence(value).is_some()
}

/// Strength of the postal address evidence in a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AddressKind {
    /// Not an address.
    None,
    /// Address-like (a street type, or a house number then a word):
    /// enough when the column name designates addresses.
    Weak,
    /// A house number with a street type in address order, a post office
    /// box, or a street type with a postcode.
    Strong,
}

struct AddrWord<'a> {
    raw: &'a str,
    folded: Zeroizing<String>,
    /// Last word of a comma / line / `$` separated segment.
    seg_end: bool,
}

fn house_number(w: &str) -> bool {
    let w = w.trim_start_matches(['#', '°', 'º']);
    let digits = w.chars().take_while(char::is_ascii_digit).count();
    if !(1..=5).contains(&digits) {
        return false;
    }
    let rest = &w[digits..];
    rest.is_empty()
        || (rest.len() == 1 && rest.chars().all(|c| c.is_ascii_alphabetic()))
        || matches!(rest.to_ascii_lowercase().as_str(), "bis" | "ter" | "quater")
        || rest
            .strip_prefix('-')
            .is_some_and(|r| (1..=5).contains(&r.len()) && r.bytes().all(|b| b.is_ascii_digit()))
}

fn street_first(f: &str) -> bool {
    lexicon::STREET_TYPES_NUMBER_FIRST.contains(&f)
}

fn street_last(f: &str) -> bool {
    lexicon::STREET_TYPES_NUMBER_LAST.contains(&f)
}

fn street_compound(w: &AddrWord<'_>) -> bool {
    w.raw.chars().next().is_some_and(char::is_uppercase)
        && lexicon::STREET_SUFFIXES
            .iter()
            .any(|s| w.folded.len() >= s.len() + 3 && w.folded.ends_with(s))
}

fn is_word(w: &AddrWord<'_>) -> bool {
    w.raw.chars().next().is_some_and(char::is_alphabetic)
}

/// Street types that make `number + words + type` an address even in
/// lower case (`12 main street`).
const STRICT_EN_TYPES: &[&str] = &[
    "street",
    "st",
    "road",
    "rd",
    "avenue",
    "ave",
    "boulevard",
    "blvd",
    "lane",
    "ln",
    "drive",
    "court",
    "ct",
    "highway",
    "hwy",
    "parkway",
    "pkwy",
    "terrace",
    "crescent",
];

fn postcode_at(ws: &[AddrWord<'_>], i: usize) -> bool {
    let w = ws[i].raw;
    let next = ws.get(i + 1);
    let next_word = next.is_some_and(is_word);
    let prev = i.checked_sub(1).map(|p| ws[p].raw);
    let b = w.as_bytes();
    let all_digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    match b.len() {
        // FR, DE, ES, IT, US: `75011 Paris`, `IL 62701`.
        5 if all_digits(b) => {
            next_word
                || prev.is_some_and(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_uppercase()))
        }
        // US ZIP+4.
        10 if all_digits(&b[..5]) && b[5] == b'-' && all_digits(&b[6..]) => true,
        // PT `1234-567`, PL `12-345`.
        8 if all_digits(&b[..4]) && b[4] == b'-' && all_digits(&b[5..]) => true,
        6 if all_digits(&b[..2]) && b[2] == b'-' && all_digits(&b[3..]) => true,
        // SE `111 22 Stockholm`.
        3 if all_digits(b)
            && next
                .is_some_and(|n| n.raw.len() == 2 && n.raw.bytes().all(|x| x.is_ascii_digit())) =>
        {
            true
        }
        // NL `1017 GC`, BE / CH / AT / DK `1000 Bruxelles` (segment start).
        4 if all_digits(b) => {
            next.is_some_and(|n| n.raw.len() == 2 && n.raw.chars().all(|c| c.is_ascii_uppercase()))
                || (next_word
                    && next.is_some_and(|n| n.raw.chars().next().is_some_and(char::is_uppercase))
                    && (i == 0 || ws[i - 1].seg_end))
        }
        // UK `NW1 6XE`, CA `H2X 1Y4`.
        2..=4 => {
            let c: Vec<char> = w.chars().map(|x| x.to_ascii_uppercase()).collect();
            let outward = c.len() >= 2
                && c[0].is_ascii_alphabetic()
                && c.iter().any(char::is_ascii_digit)
                && c.iter().all(char::is_ascii_alphanumeric);
            let inward = next.is_some_and(|n| {
                let c: Vec<char> = n.raw.chars().map(|x| x.to_ascii_uppercase()).collect();
                c.len() == 3
                    && c[0].is_ascii_digit()
                    && c[1].is_ascii_alphabetic()
                    && (c[2].is_ascii_alphabetic() || c[2].is_ascii_digit())
            });
            outward && inward
        }
        _ => {
            // `F-75011`, `CH-8001`, `D-10115`.
            w.split_once('-').is_some_and(|(c, d)| {
                (1..=2).contains(&c.len())
                    && c.chars().all(|x| x.is_ascii_uppercase())
                    && (4..=5).contains(&d.len())
                    && d.bytes().all(|x| x.is_ascii_digit())
            })
        }
    }
}

/// Analyzes a value as a postal address: FR / EN (`10 rue des Lilas`,
/// `221B Baker Street`), number-last (`Via Roma 10`, `Calle Mayor 5`,
/// `ul. Długa 5`), compound street names (`Musterstraße 12`,
/// `1 Voorbeeldstraat`), post office boxes (`PO Box 12`, `BP 123`,
/// `Postfach 10`), postcodes (FR, DE, US, UK, NL, CA, PT, PL…), abbreviated
/// street types (`av.`, `bd`, `St`, `Rd`), comma, line or LDAP `$`
/// separated.
#[must_use]
pub(crate) fn address_kind(value: &str) -> AddressKind {
    let v = value.trim();
    let len = v.chars().count();
    if !(5..=300).contains(&len)
        || v.contains('@')
        || v.contains("://")
        || !v.chars().any(char::is_alphabetic)
    {
        return AddressKind::None;
    }
    let mut ws: Vec<AddrWord<'_>> = Vec::new();
    for seg in v.split([',', ';', '$', '\n', '\r', '|']) {
        let before = ws.len();
        for raw in seg.split_whitespace() {
            let raw = raw.trim_end_matches(['.', ':']);
            if raw.is_empty() {
                continue;
            }
            ws.push(AddrWord {
                raw,
                folded: Zeroizing::new(lexicon::fold(raw).replace('.', "")),
                seg_end: false,
            });
        }
        if ws.len() > before
            && let Some(last) = ws.last_mut()
        {
            last.seg_end = true;
        }
    }
    if ws.is_empty() || ws.len() > 60 {
        return AddressKind::None;
    }
    let n = ws.len();
    let any_type = ws
        .iter()
        .any(|w| street_first(&w.folded) || street_last(&w.folded) || street_compound(w));
    let any_postcode = (0..n).any(|i| postcode_at(&ws, i));
    let digits_only = |x: &AddrWord<'_>| {
        !x.raw.is_empty() && x.raw.len() <= 6 && x.raw.bytes().all(|b| b.is_ascii_digit())
    };
    for i in 0..n {
        let w = &ws[i];
        // Post office box.
        let pobox = match w.folded.as_str() {
            "box" => i > 0 && matches!(ws[i - 1].folded.as_str(), "po" | "office" | "post"),
            "bp" | "pobox" | "postfach" | "apartado" | "postbus" | "postboks" | "casilla"
            | "pmb" | "tsa" => true,
            "postale" => i > 0 && matches!(ws[i - 1].folded.as_str(), "boite" | "case"),
            _ => false,
        };
        if pobox && ws[i + 1..(i + 3).min(n)].iter().any(digits_only) {
            return AddressKind::Strong;
        }
        // `10, rue des Lilas`: a house number, a comma, a FR street type.
        if house_number(w.raw)
            && w.seg_end
            && ws.get(i + 1).is_some_and(|x| {
                street_first(&x.folded) && !matches!(x.folded.as_str(), "st" | "dr")
            })
        {
            return AddressKind::Strong;
        }
        if house_number(w.raw) && !w.seg_end && i + 1 < n {
            // `3 bis rue`, `12 B avenue`: skip a lone suffix.
            let mut j = i + 1;
            let lone_suffix = matches!(ws[j].folded.as_str(), "bis" | "ter" | "quater")
                || (ws[j].raw.len() == 1 && ws[j].raw.chars().all(|c| c.is_ascii_uppercase()));
            if lone_suffix && j + 1 < n && !ws[j].seg_end {
                j += 1;
            }
            // FR style and compound names: `10 rue …`, `1 Voorbeeldstraat`.
            if (street_first(&ws[j].folded) && !matches!(ws[j].folded.as_str(), "st" | "dr"))
                || street_compound(&ws[j])
            {
                return AddressKind::Strong;
            }
            // EN style: `221B Baker Street`, `123 main st`.
            for k in j + 1..(j + 4).min(n) {
                if ws[k - 1].seg_end {
                    break;
                }
                if street_first(&ws[k].folded) {
                    let between = &ws[j..k];
                    let words_ok = between.iter().all(|x| {
                        is_word(x)
                            || (x.raw.len() <= 4
                                && x.raw.chars().next().is_some_and(|c| c.is_ascii_digit())
                                && ["st", "nd", "rd", "th"]
                                    .iter()
                                    .any(|s| x.folded.ends_with(s)))
                    });
                    let capitalized = between
                        .iter()
                        .all(|x| x.raw.chars().next().is_some_and(|c| !c.is_lowercase()));
                    if words_ok && (capitalized || STRICT_EN_TYPES.contains(&ws[k].folded.as_str()))
                    {
                        return AddressKind::Strong;
                    }
                    break;
                }
            }
        }
        // Number-last: `Via Roma 10`, `Musterstraße 12`, `ul. Długa 5`.
        if street_last(&w.folded) || street_compound(w) {
            for k in i + 1..(i + 5).min(n) {
                // `Via Roma, 10`: the number may follow a comma.
                if k > i + 1 && ws[k - 1].seg_end && !house_number(ws[k].raw) {
                    break;
                }
                if house_number(ws[k].raw) {
                    let names_ok = ws[i + 1..k]
                        .iter()
                        .all(|x| x.raw.chars().next().is_some_and(char::is_uppercase));
                    let ends = ws[k].seg_end || (k + 1 < n && postcode_at(&ws, k + 1));
                    if names_ok && ends {
                        return AddressKind::Strong;
                    }
                    break;
                }
            }
        }
    }
    if any_type && any_postcode {
        return AddressKind::Strong;
    }
    let leading_number = house_number(ws[0].raw)
        && ws
            .get(1)
            .is_some_and(|w| w.raw.chars().next().is_some_and(char::is_alphabetic));
    if any_type || leading_number {
        AddressKind::Weak
    } else {
        AddressKind::None
    }
}

/// A whole value shaped like a postal address ([`address_kind`], weak or
/// strong). Weak alone: the column decides.
#[must_use]
pub fn is_postal_address(value: &str) -> bool {
    address_kind(value) != AddressKind::None
}

/// A whole value shaped like an AWS secret access key: 40 characters of
/// `[A-Za-z0-9/+]` mixing upper case, lower case and digits. The column
/// decides (name hint, or a column of such values with `/` / `+`).
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

/// A whole value that is a raw hex or base64 digest (MD5, SHA-1, SHA-2,
/// NTLM), optionally with a salt (`salt:hex`, `hex$salt`). Only a password
/// hash when the column name designates passwords.
#[must_use]
pub(crate) fn is_raw_digest(value: &str) -> bool {
    let v = value.trim();
    let hex = |s: &str| {
        matches!(s.len(), 32 | 40 | 56 | 64 | 96 | 128)
            && s.bytes().all(|b| b.is_ascii_hexdigit())
            && (s.bytes().all(|b| !b.is_ascii_uppercase())
                || s.bytes().all(|b| !b.is_ascii_lowercase()))
    };
    let b64 = |s: &str| {
        matches!(s.len(), 24 | 28 | 44 | 64 | 88)
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            && !s.trim_end_matches('=').contains('=')
            && s.bytes().any(|b| b.is_ascii_digit())
            && s.bytes().any(|b| b.is_ascii_uppercase())
            && s.bytes().any(|b| b.is_ascii_lowercase())
    };
    if hex(v) || b64(v) {
        return true;
    }
    v.split_once([':', '$']).is_some_and(|(a, b)| {
        !a.is_empty() && !b.is_empty() && (hex(a) || hex(b)) && a.len().max(b.len()) <= 128
    })
}

/// Whether a string (typically a name segment) contains a value recognized
/// by a token detector. Building block for the classifier-based name
/// normalization of ADR-0009 (`crate::names` locates matches in whole names).
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
        check_patterns();
    }

    #[test]
    fn emails() {
        assert_eq!(only("jane.doe@example.com"), Some(C::Email));
        assert_eq!(only("aiden.garcía@example.org"), Some(C::Email));
        assert_eq!(only("Jane Doe <jane.doe@example.com>"), Some(C::Email));
        assert_eq!(only("mailto:jane@example.com"), Some(C::Email));
        assert_eq!(only("email=jane@example.com"), Some(C::Email));
        assert_eq!(only("Email: jane@example.com."), Some(C::Email));
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
            "https://jane@git.example.com/org/repo.git",
            "ssh://git@github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "postgres://app@db.example.com:5432/app",
            "<CAKx8=abc+XYZ@mail.gmail.com>",
            "<20240312101530.12345.abc@mx.example.com>",
            "5f8a9c2e-1b3d-4e5f-9a7b-1c2d3e4f5a6b@example.com",
            "noreply@example.com",
            "no-reply@shop.example.com",
            "MAILER-DAEMON@mx.example.com",
            "root@server.example.com",
            "admin@db01.internal",
            "icon@2x.png",
            "lodash@4.17.21",
            "@types/node@18.0.0",
            "user@example.com",
            "E1rX9Kp-0003Qx-2Z@mail.example.org",
        ] {
            assert!(found(neg).iter().all(|(c, _)| *c != C::Email), "{neg}");
        }
    }

    #[test]
    fn ibans() {
        for v in [
            "FR7630006000011234567890189",
            "FR76 3000 6000 0112 3456 7890 189",
            "fr76 3000 6000 0112 3456 7890 189",
            "FR76-3000-6000-0112-3456-7890-189",
            "DE89 3704 0044 0532 0130 00",
            "GB82WEST12345698765432",
            "gb82 west 1234 5698 7654 32",
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
        let (_, c) = scan("9111111111111111", &|_| true);
        assert!(c.card);
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
        assert_eq!(only(&format!("{} {}", &n[..13], &n[13..])), Some(C::Nir));
        assert_eq!(only(&format!("{}-{}", &n[..13], &n[13..])), Some(C::Nir));
        assert_eq!(only(&format!("{} / {}", &n[..13], &n[13..])), Some(C::Nir));
        let dotted = spaced.replace(' ', ".");
        assert_eq!(only(&dotted), Some(C::Nir));
        let bad_key = format!(
            "{}{:02}",
            &n[..13],
            (n[13..].parse::<u32>().unwrap_or(0) % 97) + 1
        );
        assert!(found(&bad_key).is_empty());
        assert!(found("385057800604812").is_empty());
        // Corsica, lower case.
        let body: u64 = "1850519006048".parse().unwrap_or(0);
        let corsica = format!("1 85 05 2a 006 048 {:02}", 97 - body % 97);
        assert_eq!(found(&corsica), [(C::Nir, corsica.as_str())]);
    }

    #[test]
    fn phones() {
        for v in [
            "01 99 00 27 59",
            "0612345678",
            "06.12.34.56.78",
            "06-12-34-56-78",
            "+33 6 12 34 56 78",
            "+33 (0)6 12 34 56 78",
            "0033 6 12 34 56 78",
            "+33612345678",
            "+1 202 555 0125",
            "+1 (202) 555-0125",
            "(202) 555-0125",
            "202-555-0125",
            "202.555.0125",
            "1-202-555-0125",
            "+44 7700 900689",
            "+44 20 7946 0958",
            "020 7946 0958",
            "07700 900123",
            "(020) 7946 0958",
            "030 12345678",
            "0151 23456789",
            "030/1234567",
            "+49 30 1234567",
            "+49-151-23456789",
            "+39 06 1234 5678",
            "+34 912 345 678",
            "+351 912 345 678",
            "+41 44 123 45 67",
            "+32 470 12 34 56",
            "+31 6 12345678",
            "+81 3-1234-5678",
            "+86 138 0013 8000",
            "+91 98765 43210",
            "+61 2 9876 5432",
            "+55 11 91234-5678",
        ] {
            assert_eq!(only(v), Some(C::Phone), "{v}");
        }
        assert_eq!(
            found("Customer called from 01 99 00 27 59 and asked to use jane@example.com."),
            [(C::Phone, "01 99 00 27 59"), (C::Email, "jane@example.com")]
        );
        assert_eq!(
            found("Call 202-555-0125 ext. 42"),
            [(C::Phone, "202-555-0125")]
        );
        for neg in [
            "1234",
            "12345678",
            "E00001",
            "1950-12-01",
            "03.05.2024",
            "03.05.2024 10:22",
            "INV-2026-000123",
            "+33",
            "9123456789012345",
            "0012345678",
            "2025550125",
            "192.168.100.200",
            "123-45-6789",
            "v1.2.3",
            "1714731720",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
        assert_eq!(phone_loose("347 123 4567"), Some(0..12));
        assert_eq!(phone_loose(" 2025550125 x12 "), Some(1..11));
        assert!(phone_loose("01/12/1950").is_none());
        assert!(phone_loose("1234").is_none());
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
        assert_eq!(only("key=AKIAIOSFODNN7EXAMPLE;"), Some(C::AwsKey));
        for neg in [
            "AKIAIOSFODNN7EXAMPL",
            "AKIAIOSFODNN7EXAMPLEX",
            "BKIAIOSFODNN7EXAMPLE",
            "xAKIAIOSFODNN7EXAMPLE",
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
        // Secret access keys in context.
        for v in [
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            r#"{"SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}"#,
            "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ] {
            assert_eq!(only(v), Some(C::AwsKey), "{v}");
        }
        assert_eq!(
            found("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").len(),
            2
        );
        assert!(found("token = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").is_empty());
    }

    #[test]
    fn password_hashes() {
        for v in [
            "$2b$12$EjXXuZ0VGWGh0JSVANuaawsTPVLWNArLzyRPleGMlMiMsUopy5qt2",
            "$2y$10$abcdefghijklmnopqrstuuWx5rRjHn3dK0y4yU5Xz6.Yq8QeFvR1a",
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
            "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$Z2hhc2hoYXNoaGFzaA",
            "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
            "$6$rounds=5000$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/",
            "$5$saltsalt$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZF6vBT8f/",
            "$1$saltsalt$qjXMvbEw8oaL.CzflDugX/",
            "$apr1$r31.....$HqJZimcKQFAMYayBlzkrA/",
            "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7",
            "$P$BjRvZQ.VQcGZlDeiKToCQd.cPw5XCe0",
            "$pbkdf2-sha256$29000$N2bMmZMSQug9Z6yVUsqZMw$Uv4mVNQpVYtvpu5qCBR7lcS5QP9n0Wkx4LJU8Z9iAdE",
            "pbkdf2_sha256$600000$saltsalt$HvZ3AOkF5r0WwFpSU7N8Dq3O3gXvKmRqLZnyXw0Gm2s=",
            "pbkdf2:sha256:600000$Xb3kQ9pL$2c6f1a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3",
            "scrypt:32768:8:1$Xb3kQ9pLmN$2c6f1a9b8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3",
            "sha1$a1b2c3$2c6f1a9b8e7d6c5b4a39281706f5e4d3c2b1a09f",
            "bcrypt_sha256$$2b$12$EjXXuZ0VGWGh0JSVANuaawsTPVLWNArLzyRPleGMlMiMsUopy5qt2",
            "{SSHA}DnKiYrOFTEkn+VpML/5/mBX+VpPyx0J0rjW88Q==",
            "{PKCS5S2}QnVpbGRlclNhbHQxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA==",
            "md5c2b1a09f8e7d6c5b4a39281706f5e4d3",
            "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9",
            "SCRAM-SHA-256$4096:c2FsdHNhbHQ=$c3RvcmVka2V5c3RvcmVka2V5:c2VydmVya2V5c2VydmVy",
        ] {
            assert_eq!(only(v), Some(C::PasswordHash), "{v}");
        }
        assert_eq!(
            only("password_hash: $2b$12$EjXXuZ0VGWGh0JSVANuaawsTPVLWNArLzyRPleGMlMiMsUopy5qt2"),
            Some(C::PasswordHash)
        );
        for neg in [
            "$2b$12$short",
            "password123",
            "{SSHA}",
            "hash: $2b$12$x",
            "$5.00",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
        assert!(is_raw_digest("5f4dcc3b5aa765d61d8327deb882cf99"));
        assert!(is_raw_digest("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"));
        assert!(!is_raw_digest("hello"));
    }

    #[test]
    fn dates() {
        for v in [
            "1950-12-01",
            "2004-02-29",
            "01/12/1950",
            "12/31/1950",
            "17.05.1980",
            "17-05-1980",
            "1980/05/17",
            "1980.05.17",
            "7/4/1980",
            "19800517",
            "1980-05-17T00:00:00Z",
            "1980-05-17 00:00:00",
            "1980-05-17T00:00:00.000+02:00",
            "1980-05-16T22:00:00.000Z",
            "17 May 1980",
            "17 mai 1980",
            "1er janvier 1980",
            "17 févr. 1980",
            "May 17, 1980",
            "January 5th, 1980",
            "17-May-1980",
            "17. Mai 1980",
            "17 de mayo de 1980",
            "Sat, 17 May 1980",
            "1980-May-17",
        ] {
            assert!(is_birth_date(v), "{v}");
        }
        for v in [
            "2024-05-03T10:22:31Z",
            "1899-01-01",
            "2003-02-29",
            "1980-13-01",
            "1980-05/17",
            "E.164",
            "17 Foo 1980",
            "12345678",
            "31/31/1980",
        ] {
            assert!(!is_birth_date(v), "{v}");
        }
        assert_eq!(
            parse_date("2024-05-03 10:22:31").map(|d| d.time),
            Some(TimeOfDay::Other)
        );
        assert_eq!(
            found("Patient born 17/05/1980, allergic."),
            [(C::BirthDate, "17/05/1980")]
        );
        assert_eq!(found("DOB: May 17, 1980"), [(C::BirthDate, "May 17, 1980")]);
        assert_eq!(
            found("née le 3 mars 1975 à Lyon"),
            [(C::BirthDate, "3 mars 1975")]
        );
    }

    #[test]
    fn person_names() {
        for v in [
            "Anaïs",
            "O'Connor",
            "AIDEN GARCÍA",
            "Jean-Pierre de la Fontaine",
            "Élodie Vincent",
            "DUPONT, Jean",
            "Dupont, Jean-Marc",
            "Mr. John Smith",
            "Mme Claire Dubois",
            "John F. Kennedy",
            "J. Smith",
            "Martin Luther King Jr.",
            "McDonald",
            "d'Angelo",
            "María José García-López",
            "Ludwig van Beethoven",
            "jean dupont",
        ] {
            assert!(is_person_name(v), "{v}");
        }
        for v in [
            "smtp_sender_domain",
            "jane@example.com",
            "Route 66",
            "strict",
            "oo-connor001",
            "a b c d e f g h",
            "",
            "Acme Corp",
            "Blue Widget",
            "Sales Manager",
            "blue widget",
            "Paris, France, Europe",
            "N/A",
        ] {
            assert!(!is_person_name(v), "{v}");
        }
        let e = name_evidence("DUPONT, Jean").unwrap_or_default();
        assert!(e.given && e.surname);
        assert_eq!(e.words, 2);
    }

    #[test]
    fn postal_addresses() {
        use AddressKind::{Strong, Weak};
        for (v, k) in [
            ("10 rue des Lilas", Strong),
            ("10, rue des Lilas, 75011 Paris", Strong),
            ("3 bis av. Foch", Strong),
            ("12 bd Haussmann", Strong),
            ("1 Voorbeeldstraat", Strong),
            ("1 allée des Peupliers, 13006 Marseille", Strong),
            ("160 Baker Street$NW1 6XE London", Strong),
            ("221B Baker Street, London NW1 6XE", Strong),
            ("1600 Pennsylvania Avenue NW, Washington, DC 20500", Strong),
            ("123 Main St", Strong),
            ("123 main street", Strong),
            ("Apt 4B, 123 Main St, Springfield, IL 62701", Strong),
            ("PO Box 1234, Springfield, IL 62701", Strong),
            ("P.O. Box 77", Strong),
            ("BP 123, 75001 Paris", Strong),
            ("Postfach 10 20 30, 10115 Berlin", Strong),
            ("Musterstraße 12, 10115 Berlin", Strong),
            ("Kerkstraat 12, 1017 GC Amsterdam", Strong),
            ("Via Roma 10, 00184 Roma", Strong),
            ("Calle Mayor 5", Strong),
            ("ul. Długa 5, 00-238 Warszawa", Strong),
            ("Storgatan 12, 111 22 Stockholm", Strong),
            ("Rua Augusta 100, 1100-053 Lisboa", Strong),
            ("10 rue des Lilas\n75011 Paris", Strong),
            ("Lieu-dit Les Granges, 12340 Bozouls", Strong),
            ("12bis avenue Foch", Strong),
            ("Place de l'Église", Weak),
            ("rue Victor Hugo", Weak),
            ("12 Grand Place", Strong),
        ] {
            assert_eq!(address_kind(v), k, "{v}");
        }
        for v in [
            "75011",
            "Paris",
            "jane@example.com 1 rue",
            "12",
            "Google Drive 15 GB",
            "sent via Email 5 times",
            "Room 101",
            "Order 12345 shipped",
            "Main Street Bakery",
        ] {
            assert_ne!(address_kind(v), Strong, "{v}");
        }
        for v in ["75011", "Paris", "Room 101", "https://example.com/rue/12"] {
            assert_eq!(address_kind(v), AddressKind::None, "{v}");
        }
    }

    #[test]
    fn filter_keeps_claims() {
        // With IBAN disabled, IBAN digits still do not become phones.
        let v = "DE07 9994 3094 0336 6126 78";
        let t = scan_tokens(v, &|c| c != C::Iban);
        assert!(t.is_empty(), "{t:?}");
    }

    /// Crafted inputs that repeat a label or an e-mail at the scan bound:
    /// the work per label / token is constant (bounded windows), so a
    /// whole value scans in far less than the generous limit below, and at
    /// most `MAX_TOKENS_PER_VALUE` tokens come out.
    #[test]
    fn crafted_repetitions_scan_in_linear_time() {
        let inputs = [
            "dob:".repeat(MAX_SCAN_BYTES / 4),
            "born ".repeat(MAX_SCAN_BYTES / 5),
            "dob: 17/05/1980 ".repeat(MAX_SCAN_BYTES / 16),
            "a@bc.fr;".repeat(MAX_SCAN_BYTES / 8),
            "x".repeat(MAX_SCAN_BYTES - 16) + "a@bc.fr",
            "a@bc.fr ".repeat(MAX_SCAN_BYTES / 8),
            "tel 01 99 00 27 59 ".repeat(MAX_SCAN_BYTES / 19),
        ];
        for v in &inputs {
            let start = std::time::Instant::now();
            let t = scan_tokens(v, &|_| true);
            let took = start.elapsed();
            assert!(t.len() <= MAX_TOKENS_PER_VALUE);
            // Debug builds on a slow CI runner included: linear scans of
            // 8 KiB take milliseconds; quadratic ones took far longer.
            assert!(took < std::time::Duration::from_secs(2), "{took:?}");
        }
    }

    #[test]
    fn long_values_are_bounded() {
        let v = format!("{}jane@example.com", "x ".repeat(MAX_SCAN_BYTES));
        assert!(found(&v).is_empty());
        assert!(bounded(&"é".repeat(MAX_SCAN_BYTES)).len() <= MAX_SCAN_BYTES);
    }
}
