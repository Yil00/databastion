//! The server schema, read from the subschema subentry (RFC 4512; ADR-0029
//! decision 5): which attributes Discovery requests, their canonical
//! names, and the structural object class of an entry.
//!
//! - Only `userApplications` attributes whose syntax (inherited through
//!   `SUP`) is in a text allow-list are requested; DN, binary, octet string,
//!   certificate, UUID and unknown syntaxes never are (fail closed).
//! - Credential attributes (`userPassword`, `authPassword`, their
//!   subtypes, and a closed list of password-equivalent hashes) are never
//!   requested, whatever their syntax (I3).
//! - Every bound is fixed: descriptions, attribute types, classes, `SUP`
//!   depth.

use std::collections::HashMap;

/// Most attribute type descriptions read.
pub(crate) const MAX_ATTRIBUTE_TYPES: usize = 4096;
/// Most object class descriptions read.
pub(crate) const MAX_CLASSES: usize = 2048;
/// Longest description parsed (longer: skipped).
pub(crate) const MAX_DESCRIPTION: usize = 8 * 1024;
/// Deepest `SUP` chain followed.
const MAX_SUP_DEPTH: usize = 16;
/// Most attributes requested by a Discovery search.
pub(crate) const MAX_REQUESTED: usize = 1024;

/// Syntaxes whose values are text the classifiers can read.
const TEXT_SYNTAXES: &[&str] = &[
    "1.3.6.1.4.1.1466.115.121.1.15", // Directory String
    "1.3.6.1.4.1.1466.115.121.1.26", // IA5 String
    "1.3.6.1.4.1.1466.115.121.1.44", // Printable String
    "1.3.6.1.4.1.1466.115.121.1.36", // Numeric String
    "1.3.6.1.4.1.1466.115.121.1.11", // Country String
    "1.3.6.1.4.1.1466.115.121.1.50", // Telephone Number
    "1.3.6.1.4.1.1466.115.121.1.41", // Postal Address
    "1.3.6.1.4.1.1466.115.121.1.24", // Generalized Time
    "1.3.6.1.4.1.1466.115.121.1.27", // Integer
];

/// Generalized Time.
pub(crate) const GENERALIZED_TIME: &str = "1.3.6.1.4.1.1466.115.121.1.24";

/// Credential attributes (lowercase names): never requested, nor any
/// attribute whose `SUP` chain reaches one of them.
const CREDENTIALS: &[&str] = &[
    "userpassword",
    "authpassword",
    "sambantpassword",
    "sambalmpassword",
    "sambapasswordhistory",
    "sambacleartextpassword",
    "krbprincipalkey",
    "krbextradata",
    "pwdhistory",
    "userpkcs12",
    "olcrootpw",
];

/// Whether a lowercase attribute name is a credential attribute of the
/// closed list.
pub(crate) fn is_credential_name(name: &str) -> bool {
    CREDENTIALS.contains(&name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token<'a> {
    Open,
    Close,
    Quoted(&'a str),
    Word(&'a str),
}

fn tokens(s: &str) -> Option<Vec<Token<'_>>> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => {
                out.push(Token::Open);
                i += 1;
            }
            b')' => {
                out.push(Token::Close);
                i += 1;
            }
            b'\'' => {
                let end = s.get(i + 1..)?.find('\'')? + i + 1;
                out.push(Token::Quoted(s.get(i + 1..end)?));
                i = end + 1;
            }
            _ => {
                let start = i;
                while bytes.get(i).is_some_and(|c| {
                    !matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')' | b'\'')
                }) {
                    i += 1;
                }
                out.push(Token::Word(s.get(start..i)?));
            }
        }
    }
    Some(out)
}

/// A value after a keyword: one token, or a parenthesized list (`$`
/// separators dropped).
fn value<'a>(toks: &[Token<'a>], pos: &mut usize) -> Option<Vec<&'a str>> {
    match toks.get(*pos)? {
        Token::Open => {
            *pos += 1;
            let mut out = Vec::new();
            loop {
                match toks.get(*pos)? {
                    Token::Close => {
                        *pos += 1;
                        return Some(out);
                    }
                    Token::Word("$") => {}
                    Token::Word(w) | Token::Quoted(w) => out.push(*w),
                    Token::Open => return None,
                }
                *pos += 1;
            }
        }
        Token::Word(w) | Token::Quoted(w) => {
            *pos += 1;
            Some(vec![*w])
        }
        Token::Close => None,
    }
}

/// Keywords that take no value.
fn is_flag(k: &str) -> bool {
    matches!(
        k,
        "OBSOLETE"
            | "SINGLE-VALUE"
            | "COLLECTIVE"
            | "NO-USER-MODIFICATION"
            | "ABSTRACT"
            | "STRUCTURAL"
            | "AUXILIARY"
    )
}

/// Keywords of a description with their values.
type Fields<'a> = Vec<(&'a str, Vec<&'a str>)>;

/// A description: its OID and its keywords with values.
fn description(s: &str) -> Option<(String, Fields<'_>)> {
    if s.len() > MAX_DESCRIPTION {
        return None;
    }
    let toks = tokens(s)?;
    if toks.first() != Some(&Token::Open) || toks.last() != Some(&Token::Close) {
        return None;
    }
    let inner = toks.get(1..toks.len() - 1)?;
    let Some(Token::Word(oid)) = inner.first() else {
        return None;
    };
    let mut pos = 1;
    let mut fields = Vec::new();
    while pos < inner.len() {
        let Some(Token::Word(k)) = inner.get(pos).cloned() else {
            return None;
        };
        pos += 1;
        if is_flag(k) {
            fields.push((k, Vec::new()));
        } else {
            fields.push((k, value(inner, &mut pos)?));
        }
    }
    Some(((*oid).to_owned(), fields))
}

/// An attribute type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttrType {
    pub(crate) oid: String,
    /// Names as the schema spells them; the first is canonical.
    pub(crate) names: Vec<String>,
    sup: Option<String>,
    syntax: Option<String>,
    user: bool,
}

fn parse_attribute_type(s: &str) -> Option<AttrType> {
    let (oid, fields) = description(s)?;
    let mut t = AttrType {
        oid,
        names: Vec::new(),
        sup: None,
        syntax: None,
        user: true,
    };
    for (k, v) in fields {
        match k {
            "NAME" => t.names = v.iter().map(|n| (*n).to_owned()).collect(),
            "SUP" => t.sup = v.first().map(|n| (*n).to_owned()),
            "SYNTAX" => {
                t.syntax = v
                    .first()
                    .map(|n| n.split('{').next().unwrap_or(n).to_owned())
            }
            "USAGE" => t.user = v.first() == Some(&"userApplications"),
            _ => {}
        }
    }
    Some(t)
}

/// An object class.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Class {
    canonical: String,
    structural: bool,
    sup: Vec<String>,
}

fn parse_class(s: &str) -> Option<(Vec<String>, Class)> {
    let (_, fields) = description(s)?;
    let mut names = Vec::new();
    let mut class = Class {
        canonical: String::new(),
        // RFC 4512: STRUCTURAL is the default kind.
        structural: true,
        sup: Vec::new(),
    };
    for (k, v) in fields {
        match k {
            "NAME" => names = v.iter().map(|n| (*n).to_owned()).collect(),
            "SUP" => class.sup = v.iter().map(|n| n.to_ascii_lowercase()).collect(),
            "ABSTRACT" | "AUXILIARY" => class.structural = false,
            _ => {}
        }
    }
    class.canonical = names.first()?.clone();
    Some((names, class))
}

/// The parts of the server schema Discovery needs.
#[derive(Debug, Default)]
pub(crate) struct Schema {
    attrs: Vec<AttrType>,
    /// Lowercase name or OID -> index in `attrs`.
    by_name: HashMap<String, usize>,
    /// Lowercase name -> class.
    classes: HashMap<String, Class>,
    /// Descriptions that did not parse or were beyond the bounds.
    pub(crate) skipped: usize,
}

impl Schema {
    /// Builds the schema from the `attributeTypes` and `objectClasses`
    /// values of the subschema subentry.
    pub(crate) fn parse<'a>(
        attribute_types: impl Iterator<Item = &'a [u8]>,
        object_classes: impl Iterator<Item = &'a [u8]>,
    ) -> Self {
        let mut s = Self::default();
        for raw in attribute_types {
            if s.attrs.len() >= MAX_ATTRIBUTE_TYPES {
                s.skipped += 1;
                continue;
            }
            match std::str::from_utf8(raw).ok().and_then(parse_attribute_type) {
                Some(t) => {
                    let i = s.attrs.len();
                    s.by_name.insert(t.oid.to_ascii_lowercase(), i);
                    for n in &t.names {
                        s.by_name.entry(n.to_ascii_lowercase()).or_insert(i);
                    }
                    s.attrs.push(t);
                }
                None => s.skipped += 1,
            }
        }
        let mut classes = 0;
        for raw in object_classes {
            if classes >= MAX_CLASSES {
                s.skipped += 1;
                continue;
            }
            match std::str::from_utf8(raw).ok().and_then(parse_class) {
                Some((names, class)) => {
                    classes += 1;
                    for n in names {
                        s.classes
                            .entry(n.to_ascii_lowercase())
                            .or_insert_with(|| class.clone());
                    }
                }
                None => s.skipped += 1,
            }
        }
        s
    }

    /// The attribute type of a description (options such as `;lang-fr`
    /// dropped), by name or OID.
    fn lookup(&self, description: &str) -> Option<&AttrType> {
        let base = description.split(';').next().unwrap_or(description);
        self.by_name
            .get(&base.to_ascii_lowercase())
            .and_then(|i| self.attrs.get(*i))
    }

    /// The `SUP` chain of an attribute, itself first (bounded).
    fn chain<'a>(&'a self, t: &'a AttrType) -> Vec<&'a AttrType> {
        let mut out = vec![t];
        let mut cur = t;
        while let Some(sup) = &cur.sup {
            if out.len() > MAX_SUP_DEPTH {
                break;
            }
            match self.by_name.get(&sup.to_ascii_lowercase()) {
                Some(i) => match self.attrs.get(*i) {
                    Some(t) => {
                        cur = t;
                        out.push(cur);
                    }
                    None => break,
                },
                None => break,
            }
        }
        out
    }

    /// The syntax of an attribute, inherited through `SUP`.
    fn syntax<'a>(&'a self, t: &'a AttrType) -> Option<&'a str> {
        self.chain(t).iter().find_map(|a| a.syntax.as_deref())
    }

    /// Whether an attribute is, or derives from, a credential attribute.
    fn is_credential(&self, t: &AttrType) -> bool {
        self.chain(t).iter().any(|a| {
            a.names
                .iter()
                .any(|n| is_credential_name(&n.to_ascii_lowercase()))
        })
    }

    /// Whether Discovery may request the attribute of `description`.
    pub(crate) fn eligible(&self, description: &str) -> bool {
        self.lookup(description).is_some_and(|t| {
            t.user
                && !t.names.is_empty()
                && !self.is_credential(t)
                && self
                    .syntax(t)
                    .is_some_and(|syn| TEXT_SYNTAXES.contains(&syn))
        })
    }

    /// Whether values of `description` are Generalized Time.
    pub(crate) fn is_time(&self, description: &str) -> bool {
        self.lookup(description)
            .and_then(|t| self.syntax(t))
            .is_some_and(|syn| syn == GENERALIZED_TIME)
    }

    /// The attributes Discovery requests: the canonical name of every
    /// eligible attribute type, sorted, at most [`MAX_REQUESTED`]. The
    /// second value counts the eligible ones left out.
    pub(crate) fn requested(&self) -> (Vec<String>, usize) {
        let mut names: Vec<String> = self
            .attrs
            .iter()
            .filter_map(|t| t.names.first())
            .filter(|n| self.eligible(n))
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        let left = names.len().saturating_sub(MAX_REQUESTED);
        names.truncate(MAX_REQUESTED);
        (names, left)
    }

    /// The canonical name of the attribute of `description`, lowercased
    /// (options dropped): the location field. `None` when unknown.
    pub(crate) fn canonical_attribute(&self, description: &str) -> Option<String> {
        self.lookup(description)
            .and_then(|t| t.names.first())
            .map(|n| n.to_ascii_lowercase())
    }

    /// The structural object class of an entry: the server's
    /// `structuralObjectClass` when the schema knows it, otherwise the most
    /// derived structural class among the entry's `objectClass` values.
    /// Canonical schema spelling.
    pub(crate) fn structural_class<'a>(
        &self,
        structural: Option<&str>,
        object_classes: impl Iterator<Item = &'a str>,
    ) -> Option<String> {
        if let Some(c) = structural.and_then(|s| self.classes.get(&s.to_ascii_lowercase())) {
            return Some(c.canonical.clone());
        }
        let found: Vec<&Class> = object_classes
            .filter_map(|n| self.classes.get(&n.to_ascii_lowercase()))
            .filter(|c| c.structural)
            .collect();
        // A class some other listed class derives from is not the most
        // derived one.
        let mut candidates: Vec<&Class> = found
            .iter()
            .copied()
            .filter(|c| {
                !found
                    .iter()
                    .any(|o| o.canonical != c.canonical && self.derives(o, &c.canonical))
            })
            .collect();
        candidates.sort_by(|a, b| a.canonical.cmp(&b.canonical));
        candidates.first().map(|c| c.canonical.clone())
    }

    /// Whether `class` derives (through `SUP`, bounded) from `ancestor`.
    fn derives(&self, class: &Class, ancestor: &str) -> bool {
        let target = ancestor.to_ascii_lowercase();
        let mut frontier: Vec<String> = class.sup.clone();
        for _ in 0..MAX_SUP_DEPTH {
            if frontier.contains(&target) {
                return true;
            }
            frontier = frontier
                .iter()
                .filter_map(|s| self.classes.get(s))
                .flat_map(|c| c.sup.iter().cloned())
                .collect();
            if frontier.is_empty() {
                break;
            }
        }
        false
    }

    /// Number of attribute types read.
    pub(crate) fn attribute_types(&self) -> usize {
        self.attrs.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A subset of the OpenLDAP 2.6 schema (core, cosine, inetorgperson,
    /// nis) and two custom definitions.
    pub(crate) const ATTRIBUTE_TYPES: &[&str] = &[
        "( 2.5.4.41 NAME 'name' DESC 'RFC4519: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
        "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name(s) for which the entity is known by' SUP name )",
        "( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC2256: last (family) name(s) for which the entity is known by' SUP name )",
        "( 2.5.4.42 NAME ( 'givenName' 'gn' ) DESC 'RFC2256: first name(s) for which the entity is known by' SUP name )",
        "( 2.5.4.35 NAME 'userPassword' DESC 'RFC4519/2307: password of user' EQUALITY octetStringMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
        "( 2.5.4.49 NAME 'distinguishedName' DESC 'RFC4519: common supertype of DN attributes' EQUALITY distinguishedNameMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
        "( 2.5.4.31 NAME 'member' DESC 'RFC2256: member of a group' SUP distinguishedName )",
        "( 0.9.2342.19200300.100.1.3 NAME ( 'mail' 'rfc822Mailbox' ) DESC 'RFC1274: RFC822 Mailbox' EQUALITY caseIgnoreIA5Match SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{256} )",
        "( 2.5.4.20 NAME 'telephoneNumber' DESC 'RFC2256: Telephone Number' EQUALITY telephoneNumberMatch SUBSTR telephoneNumberSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.50{32} )",
        "( 2.5.4.16 NAME 'postalAddress' DESC 'RFC2256: postal address' EQUALITY caseIgnoreListMatch SUBSTR caseIgnoreListSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
        "( 0.9.2342.19200300.100.1.60 NAME 'jpegPhoto' DESC 'RFC2798: a JPEG image' SYNTAX 1.3.6.1.4.1.1466.115.121.1.28 )",
        "( 2.5.18.1 NAME 'createTimestamp' DESC 'RFC4512: time which object was created' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
        "( 2.5.4.0 NAME 'objectClass' DESC 'RFC4512: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
        "( 1.3.6.1.4.1.7165.2.1.25 NAME 'sambaNTPassword' DESC 'MD4 hash of the unicode password' EQUALITY caseIgnoreIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{32} SINGLE-VALUE )",
        "( 1.3.6.1.4.1.99999.1 NAME 'appSecretPassword' DESC 'custom subtype' SUP userPassword )",
        "( 1.3.6.1.4.1.99999.2 NAME 'contractorBirth' DESC 'custom date' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
        "( 1.3.6.1.4.1.99999.3 NAME 'contractorNir' DESC 'custom' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN ( 'dev' 'test' ) )",
        "( 1.3.6.1.4.1.99999.4 NAME 'loopA' SUP loopB )",
        "( 1.3.6.1.4.1.99999.5 NAME 'loopB' SUP loopA )",
        "not a description",
    ];

    pub(crate) const OBJECT_CLASSES: &[&str] = &[
        "( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
        "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
        "( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ x121Address ) )",
        "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' DESC 'RFC2798: Internet Organizational Person' SUP organizationalPerson STRUCTURAL MAY ( audio $ mail ) )",
        "( 2.5.6.5 NAME 'organizationalUnit' DESC 'RFC2256: an organizational unit' SUP top STRUCTURAL MUST ou )",
        "( 0.9.2342.19200300.100.4.19 NAME 'simpleSecurityObject' DESC 'RFC1274: simple security object' SUP top AUXILIARY MUST userPassword )",
    ];

    pub(crate) fn schema() -> Schema {
        Schema::parse(
            ATTRIBUTE_TYPES.iter().map(|s| s.as_bytes()),
            OBJECT_CLASSES.iter().map(|s| s.as_bytes()),
        )
    }

    #[test]
    fn eligible_attributes_are_text_user_attributes_without_credentials() {
        let s = schema();
        assert_eq!(s.skipped, 1);
        assert!(s.eligible("cn"));
        assert!(s.eligible("commonName"));
        assert!(s.eligible("CN;lang-fr"));
        assert!(s.eligible("mail"));
        assert!(s.eligible("telephoneNumber"));
        assert!(s.eligible("postalAddress"));
        assert!(s.eligible("contractorNir"));
        assert!(s.eligible("contractorBirth"));
        // Credentials, whatever the syntax, and their subtypes.
        assert!(!s.eligible("userPassword"));
        assert!(!s.eligible("userPassword;binary"));
        assert!(!s.eligible("appSecretPassword"));
        assert!(!s.eligible("sambaNTPassword"));
        // DN references, binaries, operational attributes, OIDs, unknown,
        // and a SUP loop without syntax.
        assert!(!s.eligible("member"));
        assert!(!s.eligible("jpegPhoto"));
        assert!(!s.eligible("createTimestamp"));
        assert!(!s.eligible("objectClass"));
        assert!(!s.eligible("nosuch"));
        assert!(!s.eligible("loopA"));
        let (requested, left) = s.requested();
        assert_eq!(left, 0);
        assert_eq!(
            requested,
            [
                "cn",
                "contractorBirth",
                "contractorNir",
                "givenName",
                "mail",
                "name",
                "postalAddress",
                "sn",
                "telephoneNumber"
            ]
        );
        assert!(s.is_time("contractorBirth"));
        assert!(!s.is_time("cn"));
        assert_eq!(
            s.canonical_attribute("commonName;lang-fr").as_deref(),
            Some("cn")
        );
        assert_eq!(
            s.canonical_attribute("RFC822MAILBOX").as_deref(),
            Some("mail")
        );
        assert_eq!(s.canonical_attribute("unknown"), None);
    }

    #[test]
    fn structural_classes() {
        let s = schema();
        assert_eq!(
            s.structural_class(Some("inetorgperson"), std::iter::empty())
                .as_deref(),
            Some("inetOrgPerson")
        );
        // Without structuralObjectClass: the most derived structural class.
        assert_eq!(
            s.structural_class(
                None,
                [
                    "top",
                    "person",
                    "inetOrgPerson",
                    "organizationalPerson",
                    "simpleSecurityObject"
                ]
                .into_iter()
            )
            .as_deref(),
            Some("inetOrgPerson")
        );
        assert_eq!(
            s.structural_class(None, ["simpleSecurityObject"].into_iter()),
            None
        );
    }

    #[test]
    fn descriptions_are_bounded_and_fail_closed() {
        assert!(description(&format!("( 1.2 DESC '{}' )", "x".repeat(MAX_DESCRIPTION))).is_none());
        assert!(description("( 1.2 NAME 'unterminated )").is_none());
        assert!(description("( 1.2 NAME ( 'a' ( 'b' ) ) )").is_none());
        assert!(description("1.2 NAME 'a'").is_none());
        let (oid, fields) = description("( 1.2 NAME ( 'a' $ 'b' ) SINGLE-VALUE )").unwrap();
        assert_eq!(oid, "1.2");
        assert_eq!(fields[0], ("NAME", vec!["a", "b"]));
        assert_eq!(fields[1], ("SINGLE-VALUE", vec![]));
    }
}
