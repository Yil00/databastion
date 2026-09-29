//! The closed LDAPv3 subset of the connector (RFC 4511; ADR-0029 decision
//! 1): the requests it can encode and the responses it can read.
//!
//! Requests: `BindRequest` (simple, SASL `EXTERNAL`), `SearchRequest`,
//! `ExtendedRequest` (StartTLS, Who am I?), `UnbindRequest`. There is no
//! encoder for any write operation, compare or abandon: the connector
//! cannot send one (I4).
//!
//! Responses keep the result code only: `matchedDN`, `diagnosticMessage`
//! and referral URIs are skipped without being copied (server text can
//! quote values and entry DNs). Search entries keep their DN and attribute
//! values in zeroized buffers.

use zeroize::Zeroizing;

use crate::ber::{self, BerError, ENUMERATED, Enc, INTEGER, OCTET_STRING, Reader, SEQUENCE, SET};

/// StartTLS (RFC 4511 section 4.14).
pub(crate) const OID_START_TLS: &str = "1.3.6.1.4.1.1466.20037";
/// Who am I? (RFC 4532).
pub(crate) const OID_WHOAMI: &str = "1.3.6.1.4.1.4203.1.11.3";
/// Notice of Disconnection (unsolicited).
const OID_NOTICE_OF_DISCONNECTION: &str = "1.3.6.1.4.1.1466.20036";

/// Most attribute values kept per entry (beyond: skipped, counted).
pub(crate) const MAX_VALUES_PER_ENTRY: usize = 4096;
/// Longest attribute description accepted (longer: the attribute is
/// skipped).
const MAX_ATTR_NAME: usize = 256;

/// Search scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Base,
    One,
    Sub,
}

impl Scope {
    fn code(self) -> i64 {
        match self {
            Self::Base => 0,
            Self::One => 1,
            Self::Sub => 2,
        }
    }
}

/// A search filter built by the connector (never parsed from input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    /// `(attr=value)`.
    Eq(&'static str, String),
    /// `(attr=*)`.
    Present(&'static str),
    /// `(attr>=value)`.
    Ge(&'static str, String),
    /// `(attr:rule:=value)`.
    Extensible {
        rule: &'static str,
        attr: &'static str,
        value: String,
    },
}

impl Filter {
    fn encode(&self) -> Enc {
        match self {
            Self::And(items) => Enc::constructed(
                ber::ctx_constructed(0),
                &items.iter().map(Self::encode).collect::<Vec<_>>(),
            ),
            Self::Or(items) => Enc::constructed(
                ber::ctx_constructed(1),
                &items.iter().map(Self::encode).collect::<Vec<_>>(),
            ),
            Self::Eq(attr, value) => Enc::constructed(
                ber::ctx_constructed(3),
                &[
                    Enc::octets(OCTET_STRING, attr.as_bytes()),
                    Enc::octets(OCTET_STRING, value.as_bytes()),
                ],
            ),
            Self::Ge(attr, value) => Enc::constructed(
                ber::ctx_constructed(5),
                &[
                    Enc::octets(OCTET_STRING, attr.as_bytes()),
                    Enc::octets(OCTET_STRING, value.as_bytes()),
                ],
            ),
            Self::Present(attr) => Enc::octets(ber::ctx(7), attr.as_bytes()),
            Self::Extensible { rule, attr, value } => Enc::constructed(
                ber::ctx_constructed(9),
                &[
                    Enc::octets(ber::ctx(1), rule.as_bytes()),
                    Enc::octets(ber::ctx(2), attr.as_bytes()),
                    Enc::octets(ber::ctx(3), value.as_bytes()),
                ],
            ),
        }
    }
}

/// A search request.
#[derive(Debug, Clone)]
pub(crate) struct Search<'a> {
    pub(crate) base: &'a str,
    pub(crate) scope: Scope,
    /// Entries at most (`0` is never sent: no limit).
    pub(crate) size_limit: u32,
    /// Seconds (at least 1).
    pub(crate) time_limit: u32,
    pub(crate) types_only: bool,
    pub(crate) filter: Filter,
    /// Requested attributes; empty is never sent (it means "all user
    /// attributes"): use `["1.1"]` for none.
    pub(crate) attributes: &'a [&'a str],
}

/// `LDAPMessage` around a protocol operation.
fn message(id: i32, op: Enc) -> Enc {
    Enc::constructed(SEQUENCE, &[Enc::int(INTEGER, i64::from(id)), op])
}

/// Simple bind (LDAPv3). The caller refuses an empty password.
pub(crate) fn bind_simple(id: i32, dn: &str, password: &str) -> Enc {
    message(
        id,
        Enc::constructed(
            ber::app(0),
            &[
                Enc::int(INTEGER, 3),
                Enc::octets(OCTET_STRING, dn.as_bytes()),
                Enc::octets(ber::ctx(0), password.as_bytes()),
            ],
        ),
    )
}

/// SASL `EXTERNAL` bind with an empty initial response (no authorization
/// identity: the server derives it from the transport). Without the
/// initial response, slapd answers `saslBindInProgress` (14) and waits for
/// a second step (checked against slapd 2.6).
pub(crate) fn bind_sasl_external(id: i32) -> Enc {
    message(
        id,
        Enc::constructed(
            ber::app(0),
            &[
                Enc::int(INTEGER, 3),
                Enc::octets(OCTET_STRING, b""),
                Enc::constructed(
                    ber::ctx_constructed(3),
                    &[
                        Enc::octets(OCTET_STRING, b"EXTERNAL"),
                        Enc::octets(OCTET_STRING, b""),
                    ],
                ),
            ],
        ),
    )
}

/// A search request. `derefAliases` is always `neverDerefAliases`.
pub(crate) fn search(id: i32, s: &Search<'_>) -> Enc {
    let attributes: Vec<Enc> = s
        .attributes
        .iter()
        .map(|a| Enc::octets(OCTET_STRING, a.as_bytes()))
        .collect();
    message(
        id,
        Enc::constructed(
            ber::app(3),
            &[
                Enc::octets(OCTET_STRING, s.base.as_bytes()),
                Enc::int(ENUMERATED, s.scope.code()),
                Enc::int(ENUMERATED, 0),
                Enc::int(INTEGER, i64::from(s.size_limit.max(1))),
                Enc::int(INTEGER, i64::from(s.time_limit.max(1))),
                Enc::boolean(s.types_only),
                s.filter.encode(),
                Enc::constructed(SEQUENCE, &attributes),
            ],
        ),
    )
}

/// An extended request without a value (StartTLS, Who am I?).
pub(crate) fn extended(id: i32, oid: &str) -> Enc {
    message(
        id,
        Enc::constructed(ber::app(23), &[Enc::octets(ber::ctx(0), oid.as_bytes())]),
    )
}

/// Unbind.
pub(crate) fn unbind(id: i32) -> Enc {
    message(id, Enc::octets(ber::app_primitive(2), b""))
}

/// One attribute of an entry: its description (as the server sent it)
/// and its values.
pub(crate) struct Attribute {
    pub(crate) name: String,
    pub(crate) values: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attribute")
            .field("values", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// A search result entry.
pub(crate) struct Entry {
    pub(crate) dn: Zeroizing<String>,
    pub(crate) attributes: Vec<Attribute>,
    /// Values beyond [`MAX_VALUES_PER_ENTRY`], or attributes with an
    /// oversized description, skipped.
    pub(crate) skipped: usize,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("attributes", &self.attributes.len())
            .field("skipped", &self.skipped)
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// Values of the attribute `name` (description compared
    /// case-insensitively, options excluded).
    pub(crate) fn values(&self, name: &str) -> impl Iterator<Item = &[u8]> {
        self.attributes
            .iter()
            .filter(move |a| a.name.eq_ignore_ascii_case(name))
            .flat_map(|a| a.values.iter().map(|v| v.as_slice()))
    }

    /// The first value of `name` as UTF-8.
    pub(crate) fn first_str(&self, name: &str) -> Option<&str> {
        self.values(name)
            .next()
            .and_then(|v| std::str::from_utf8(v).ok())
    }
}

/// A protocol operation received from the server.
#[derive(Debug)]
pub(crate) enum Response {
    Bind {
        code: u32,
    },
    Entry(Entry),
    /// A continuation reference (never followed).
    Reference,
    Done {
        code: u32,
    },
    Extended {
        code: u32,
        value: Option<Zeroizing<Vec<u8>>>,
    },
    /// An intermediate response (ignored).
    Intermediate,
}

/// A received message: its id and operation.
#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) id: i32,
    pub(crate) op: Response,
}

/// Why a message is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Malformed BER or LDAP.
    Malformed,
    /// An unsolicited Notice of Disconnection.
    Disconnected,
}

impl From<BerError> for ParseError {
    fn from(_: BerError) -> Self {
        Self::Malformed
    }
}

/// `LDAPResult`: the result code; `matchedDN`, `diagnosticMessage` and
/// `referral` are skipped.
fn result_code(r: &mut Reader<'_>) -> Result<u32, ParseError> {
    let code = r.int(ENUMERATED)?;
    r.expect(OCTET_STRING)?;
    r.expect(OCTET_STRING)?;
    r.optional(ber::ctx_constructed(3))?;
    u32::try_from(code).map_err(|_| ParseError::Malformed)
}

fn utf8(bytes: &[u8]) -> Result<String, ParseError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| ParseError::Malformed)
}

fn entry(r: &mut Reader<'_>) -> Result<Entry, ParseError> {
    let dn = Zeroizing::new(
        std::str::from_utf8(r.expect(OCTET_STRING)?)
            .map_err(|_| ParseError::Malformed)?
            .to_owned(),
    );
    let mut list = r.nested(SEQUENCE)?;
    if !r.is_empty() {
        return Err(ParseError::Malformed);
    }
    let mut attributes = Vec::new();
    let mut kept = 0usize;
    let mut skipped = 0usize;
    while !list.is_empty() {
        let mut attr = list.nested(SEQUENCE)?;
        let name = attr.expect(OCTET_STRING)?;
        let mut vals = attr.nested(SET)?;
        if !attr.is_empty() {
            return Err(ParseError::Malformed);
        }
        let usable = name.len() <= MAX_ATTR_NAME
            && !name.is_empty()
            && name
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b';' | b'.'));
        let mut values = Vec::new();
        while !vals.is_empty() {
            let v = vals.expect(OCTET_STRING)?;
            if usable && kept < MAX_VALUES_PER_ENTRY {
                values.push(Zeroizing::new(v.to_vec()));
                kept += 1;
            } else {
                skipped += 1;
            }
        }
        if usable {
            attributes.push(Attribute {
                name: utf8(name)?,
                values,
            });
        } else {
            skipped += 1;
        }
    }
    Ok(Entry {
        dn,
        attributes,
        skipped,
    })
}

/// Parses one `LDAPMessage` (the whole buffer). Controls are skipped.
pub(crate) fn parse(buf: &[u8]) -> Result<Message, ParseError> {
    let mut outer = Reader::new(buf);
    let mut msg = outer.nested(SEQUENCE)?;
    if !outer.is_empty() {
        return Err(ParseError::Malformed);
    }
    let id = i32::try_from(msg.int(INTEGER)?).map_err(|_| ParseError::Malformed)?;
    if id < 0 {
        return Err(ParseError::Malformed);
    }
    let (tag, content) = msg.tlv()?;
    // Optional controls ([0]), then nothing.
    msg.optional(ber::ctx_constructed(0))?;
    if !msg.is_empty() {
        return Err(ParseError::Malformed);
    }
    let mut r = Reader::new(content);
    let op = match tag {
        t if t == ber::app(1) => {
            let code = result_code(&mut r)?;
            // serverSaslCreds [7]: skipped.
            r.optional(ber::ctx(7))?;
            Response::Bind { code }
        }
        t if t == ber::app(4) => Response::Entry(entry(&mut r)?),
        t if t == ber::app(5) => Response::Done {
            code: result_code(&mut r)?,
        },
        t if t == ber::app(19) => {
            // SEQUENCE OF URI: checked for form, never read.
            while !r.is_empty() {
                r.expect(OCTET_STRING)?;
            }
            Response::Reference
        }
        t if t == ber::app(24) => {
            let code = result_code(&mut r)?;
            let name = r.optional(ber::ctx(10))?.map(utf8).transpose()?;
            let value = r
                .optional(ber::ctx(11))?
                .map(|v| Zeroizing::new(v.to_vec()));
            if id == 0 && name.as_deref() == Some(OID_NOTICE_OF_DISCONNECTION) {
                return Err(ParseError::Disconnected);
            }
            Response::Extended { code, value }
        }
        t if t == ber::app(25) => Response::Intermediate,
        _ => return Err(ParseError::Malformed),
    };
    if !r.is_empty() && !matches!(op, Response::Intermediate) {
        return Err(ParseError::Malformed);
    }
    if id == 0 {
        // Only a Notice of Disconnection may be unsolicited.
        return Err(ParseError::Malformed);
    }
    Ok(Message { id, op })
}

/// `BOOLEAN` content.
#[cfg(test)]
pub(crate) fn decode_bool(content: &[u8]) -> Option<bool> {
    match content {
        [0] => Some(false),
        [_] => Some(true),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod encode {
    //! Server-side encoders for the scripted server and the tests.
    use super::*;

    fn ldap_result(code: u32) -> Vec<Enc> {
        vec![
            Enc::int(ENUMERATED, i64::from(code)),
            Enc::octets(OCTET_STRING, b"matched-DN-uid=SECRET"),
            Enc::octets(OCTET_STRING, b"diagnostic SECRET text"),
        ]
    }

    pub(crate) fn bind_response(id: i32, code: u32) -> Vec<u8> {
        message(id, Enc::constructed(ber::app(1), &ldap_result(code)))
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn done(id: i32, code: u32) -> Vec<u8> {
        message(id, Enc::constructed(ber::app(5), &ldap_result(code)))
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn extended_response(id: i32, code: u32, value: Option<&[u8]>) -> Vec<u8> {
        let mut parts = ldap_result(code);
        if let Some(v) = value {
            parts.push(Enc::octets(ber::ctx(11), v));
        }
        message(id, Enc::constructed(ber::app(24), &parts))
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn notice_of_disconnection() -> Vec<u8> {
        let mut parts = ldap_result(52);
        parts.push(Enc::octets(
            ber::ctx(10),
            OID_NOTICE_OF_DISCONNECTION.as_bytes(),
        ));
        message(0, Enc::constructed(ber::app(24), &parts))
            .as_bytes()
            .to_vec()
    }

    pub(crate) fn reference(id: i32) -> Vec<u8> {
        message(
            id,
            Enc::constructed(
                ber::app(19),
                &[Enc::octets(
                    OCTET_STRING,
                    b"ldap://elsewhere.example/dc=x??sub",
                )],
            ),
        )
        .as_bytes()
        .to_vec()
    }

    pub(crate) fn entry(id: i32, dn: &str, attrs: &[(&str, &[&[u8]])]) -> Vec<u8> {
        let list: Vec<Enc> = attrs
            .iter()
            .map(|(name, values)| {
                Enc::constructed(
                    SEQUENCE,
                    &[
                        Enc::octets(OCTET_STRING, name.as_bytes()),
                        Enc::constructed(
                            SET,
                            &values
                                .iter()
                                .map(|v| Enc::octets(OCTET_STRING, v))
                                .collect::<Vec<_>>(),
                        ),
                    ],
                )
            })
            .collect();
        message(
            id,
            Enc::constructed(
                ber::app(4),
                &[
                    Enc::octets(OCTET_STRING, dn.as_bytes()),
                    Enc::constructed(SEQUENCE, &list),
                ],
            ),
        )
        .as_bytes()
        .to_vec()
    }
}

/// A request as the scripted server sees it.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    BindSimple {
        dn: String,
        password: String,
    },
    BindSasl {
        mechanism: String,
    },
    Search {
        base: String,
        scope: i64,
        size_limit: i64,
        types_only: bool,
        filter: String,
        attributes: Vec<String>,
    },
    Extended {
        oid: String,
    },
    Unbind,
}

/// Decodes a client request (scripted server only).
#[cfg(test)]
pub(crate) fn parse_request(buf: &[u8]) -> Option<(i32, Request)> {
    use crate::ber::BOOLEAN;
    fn filter_text(tag: u8, content: &[u8]) -> Option<String> {
        let mut r = Reader::new(content);
        Some(match tag {
            0xa0 | 0xa1 => {
                let mut s = String::from(if tag == 0xa0 { "(&" } else { "(|" });
                while !r.is_empty() {
                    let (t, c) = r.tlv().ok()?;
                    s.push_str(&filter_text(t, c)?);
                }
                s.push(')');
                s
            }
            0xa3 | 0xa5 => {
                let a = std::str::from_utf8(r.expect(OCTET_STRING).ok()?).ok()?;
                let v = std::str::from_utf8(r.expect(OCTET_STRING).ok()?).ok()?;
                format!("({a}{}{v})", if tag == 0xa3 { "=" } else { ">=" })
            }
            0x87 => format!("({}=*)", std::str::from_utf8(content).ok()?),
            0xa9 => {
                let rule = std::str::from_utf8(r.expect(ber::ctx(1)).ok()?).ok()?;
                let a = std::str::from_utf8(r.expect(ber::ctx(2)).ok()?).ok()?;
                let v = std::str::from_utf8(r.expect(ber::ctx(3)).ok()?).ok()?;
                format!("({a}:{rule}:={v})")
            }
            _ => return None,
        })
    }
    let mut outer = Reader::new(buf);
    let mut msg = outer.nested(SEQUENCE).ok()?;
    let id = i32::try_from(msg.int(INTEGER).ok()?).ok()?;
    let (tag, content) = msg.tlv().ok()?;
    let mut r = Reader::new(content);
    let s = |b: &[u8]| String::from_utf8(b.to_vec()).ok();
    let req = match tag {
        0x60 => {
            r.int(INTEGER).ok()?;
            let dn = s(r.expect(OCTET_STRING).ok()?)?;
            match r.tlv().ok()? {
                (0x80, pw) => Request::BindSimple {
                    dn,
                    password: s(pw)?,
                },
                (0xa3, sasl) => Request::BindSasl {
                    mechanism: s(Reader::new(sasl).expect(OCTET_STRING).ok()?)?,
                },
                _ => return None,
            }
        }
        0x63 => {
            let base = s(r.expect(OCTET_STRING).ok()?)?;
            let scope = r.int(ENUMERATED).ok()?;
            r.int(ENUMERATED).ok()?;
            let size_limit = r.int(INTEGER).ok()?;
            r.int(INTEGER).ok()?;
            let types_only = decode_bool(r.expect(BOOLEAN).ok()?)?;
            let (t, c) = r.tlv().ok()?;
            let filter = filter_text(t, c)?;
            let mut list = r.nested(SEQUENCE).ok()?;
            let mut attributes = Vec::new();
            while !list.is_empty() {
                attributes.push(s(list.expect(OCTET_STRING).ok()?)?);
            }
            Request::Search {
                base,
                scope,
                size_limit,
                types_only,
                filter,
                attributes,
            }
        }
        0x77 => Request::Extended {
            oid: s(r.expect(ber::ctx(0)).ok()?)?,
        },
        0x42 => Request::Unbind,
        _ => return None,
    };
    Some((id, req))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_through_the_scripted_decoder() {
        let (id, req) = parse_request(bind_simple(1, "cn=a,dc=x", "pw").as_bytes()).unwrap();
        assert_eq!(id, 1);
        assert_eq!(
            req,
            Request::BindSimple {
                dn: "cn=a,dc=x".to_owned(),
                password: "pw".to_owned()
            }
        );
        let (_, req) = parse_request(bind_sasl_external(2).as_bytes()).unwrap();
        assert_eq!(
            req,
            Request::BindSasl {
                mechanism: "EXTERNAL".to_owned()
            }
        );
        let filter = Filter::And(vec![
            Filter::Eq("objectClass", "auditSearch".to_owned()),
            Filter::Extensible {
                rule: "dnSubtreeMatch",
                attr: "reqDN",
                value: "dc=x".to_owned(),
            },
            Filter::Ge("entryCSN", "2026".to_owned()),
            Filter::Or(vec![Filter::Present("objectClass")]),
        ]);
        let search_req = Search {
            base: "cn=accesslog",
            scope: Scope::One,
            size_limit: 10,
            time_limit: 3,
            types_only: true,
            filter,
            attributes: &["1.1"],
        };
        let (_, req) = parse_request(search(3, &search_req).as_bytes()).unwrap();
        assert_eq!(
            req,
            Request::Search {
                base: "cn=accesslog".to_owned(),
                scope: 1,
                size_limit: 10,
                types_only: true,
                filter: "(&(objectClass=auditSearch)(reqDN:dnSubtreeMatch:=dc=x)\
                         (entryCSN>=2026)(|(objectClass=*)))"
                    .to_owned(),
                attributes: vec!["1.1".to_owned()],
            }
        );
        assert_eq!(
            parse_request(extended(4, OID_WHOAMI).as_bytes()).unwrap().1,
            Request::Extended {
                oid: OID_WHOAMI.to_owned()
            }
        );
        assert_eq!(
            parse_request(unbind(5).as_bytes()).unwrap().1,
            Request::Unbind
        );
    }

    #[test]
    fn responses_keep_codes_and_entries_only() {
        let m = parse(&encode::bind_response(1, 49)).unwrap();
        assert!(matches!(m.op, Response::Bind { code: 49 }));
        assert_eq!(m.id, 1);
        let m = parse(&encode::done(2, 0)).unwrap();
        assert!(matches!(m.op, Response::Done { code: 0 }));
        let m = parse(&encode::entry(
            3,
            "uid=jdoe,ou=people,dc=x",
            &[
                ("mail", &[b"a@example.org", b"b@example.org"]),
                ("cn", &[b"J"]),
            ],
        ))
        .unwrap();
        let Response::Entry(e) = m.op else {
            panic!("not an entry")
        };
        assert_eq!(e.dn.as_str(), "uid=jdoe,ou=people,dc=x");
        assert_eq!(e.values("MAIL").count(), 2);
        assert_eq!(e.first_str("cn"), Some("J"));
        let m = parse(&encode::extended_response(4, 0, Some(b"dn:cn=a"))).unwrap();
        assert!(matches!(m.op, Response::Extended { code: 0, .. }));
        assert!(matches!(
            parse(&encode::reference(5)).unwrap().op,
            Response::Reference
        ));
        assert_eq!(
            parse(&encode::notice_of_disconnection()).unwrap_err(),
            ParseError::Disconnected
        );
        // Server text never reaches the debug output of a parsed message.
        let dbg = format!("{:?}", parse(&encode::done(2, 50)).unwrap());
        assert!(!dbg.contains("SECRET"), "{dbg}");
    }

    #[test]
    fn unexpected_shapes_are_refused() {
        // A response to message 0 that is not a notice of disconnection.
        assert!(parse(&encode::done(0, 0)).is_err());
        // Trailing bytes after the message.
        let mut two = encode::done(1, 0);
        two.extend_from_slice(&encode::done(2, 0));
        assert!(parse(&two).is_err());
        // A request tag in a response.
        assert!(parse(unbind(1).as_bytes()).is_err());
        // An empty sequence (the input that panics other decoders).
        assert!(parse(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn attribute_names_outside_the_description_charset_are_skipped() {
        let m = parse(&encode::entry(
            1,
            "cn=x",
            &[("bad name", &[b"v"]), ("good;lang-fr", &[b"w"])],
        ))
        .unwrap();
        let Response::Entry(e) = m.op else {
            panic!("not an entry")
        };
        assert_eq!(e.attributes.len(), 1);
        assert_eq!(e.skipped, 2);
    }
}
