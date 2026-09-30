//! `cn=accesslog` entries reduced to closed facts (ADR-0029 decision 7).
//!
//! Read: `reqType`, `reqStart`, `reqSession`, `reqAuthzID`, `reqDN`,
//! `reqResult`, `reqScope`, `reqFilter` (reduced at once by
//! [`super::filter`]), `reqAttr` (attribute names), `reqAttrsOnly`,
//! `reqEntries`, `reqSizeLimit`, `reqMethod`, `entryCSN`. Never requested:
//! `reqMod`, `reqOld`, `reqAssertion`, `reqMessage`, `reqControls`,
//! `reqRespControls`, `reqData`, `reqReferral`, `reqNewRDN`,
//! `reqNewSuperior`.

use std::time::SystemTime;

use zeroize::Zeroizing;

use super::filter::{self, Facts};
use crate::dn;
use crate::proto::Entry;
use crate::schema::is_credential_name;
use crate::time;

/// The attributes the stream requests from the log.
pub(crate) const LOG_ATTRIBUTES: [&str; 14] = [
    "reqType",
    "reqStart",
    "reqSession",
    "reqAuthzID",
    "reqDN",
    "reqResult",
    "reqScope",
    "reqFilter",
    "reqAttr",
    "reqAttrsOnly",
    "reqEntries",
    "reqSizeLimit",
    "reqMethod",
    "entryCSN",
];

/// Stands for a `reqDN` longer than `dn::MAX_DN_BYTES`.
pub(crate) const OVERSIZED_DN: &str = "#oversized";
/// Most `reqAttr` values examined.
const MAX_REQ_ATTRS: usize = 2048;

/// The operation of a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Search,
    Compare,
    /// `sasl`: a SASL bind (no DN in the record).
    Bind {
        sasl: bool,
    },
    /// `add`, `delete`, `modify` (password changes included), `modrdn`.
    Write,
    Unbind,
    /// `abandon`, extended operations, anything else: no event.
    Other,
}

/// `reqScope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogScope {
    Base,
    One,
    Sub,
    Subord,
}

/// What a search asked for (`reqAttr`), names only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Requested {
    /// Names listed.
    pub(crate) listed: usize,
    /// Only `1.1` (no attribute).
    pub(crate) none: bool,
    /// `*`, or no list at all (every user attribute).
    pub(crate) all_user: bool,
    /// `+` (every operational attribute).
    pub(crate) operational: bool,
    /// A credential attribute of the closed list (`userPassword`…).
    pub(crate) credential: bool,
    /// Every name listed is a credential attribute.
    pub(crate) only_credential: bool,
}

/// One log entry, reduced.
pub(crate) struct Record {
    pub(crate) csn: String,
    pub(crate) op: Op,
    pub(crate) start: SystemTime,
    pub(crate) session: Option<u64>,
    /// `reqAuthzID`, canonical; `None` for anonymous (empty). A person's
    /// DN embeds values: memory only, zeroized (end-of-phase-6 review I4).
    pub(crate) authz: Option<Zeroizing<String>>,
    /// `reqDN` as logged (entry DNs embed values: memory only).
    pub(crate) target: Zeroizing<String>,
    /// Canonical `reqDN`.
    pub(crate) target_canon: Zeroizing<String>,
    pub(crate) result: u32,
    pub(crate) scope: Option<LogScope>,
    pub(crate) filter: Facts,
    pub(crate) requested: Requested,
    pub(crate) attrs_only: bool,
    pub(crate) entries: Option<u64>,
    pub(crate) size_limit: Option<i64>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("op", &self.op)
            .field("result", &self.result)
            .field("scope", &self.scope)
            .field("entries", &self.entries)
            .finish_non_exhaustive()
    }
}

fn number(e: &Entry, name: &str) -> Option<i64> {
    e.first_str(name).and_then(|s| s.trim().parse().ok())
}

fn requested(e: &Entry) -> Requested {
    let mut r = Requested {
        only_credential: true,
        ..Requested::default()
    };
    for v in e.values("reqAttr").take(MAX_REQ_ATTRS) {
        r.listed += 1;
        let name = String::from_utf8_lossy(v).to_ascii_lowercase();
        let base = name.split(';').next().unwrap_or_default().to_owned();
        match base.as_str() {
            "*" => r.all_user = true,
            "+" => r.operational = true,
            _ => {}
        }
        let credential = is_credential_name(&base);
        r.credential |= credential;
        r.only_credential &= credential;
    }
    if r.listed == 0 {
        r.all_user = true;
        r.only_credential = false;
    }
    r.none = r.listed == 1 && e.values("reqAttr").next().is_some_and(|v| v == b"1.1");
    r
}

/// Reduces a log entry. `Err(())` when it cannot be read (counted as
/// dropped).
pub(crate) fn parse(e: &Entry) -> Result<Record, ()> {
    let csn = e
        .first_str("entryCSN")
        .filter(|c| time::valid_csn(c))
        .ok_or(())?;
    let kind = e.first_str("reqType").ok_or(())?;
    let op = match kind {
        "search" => Op::Search,
        "compare" => Op::Compare,
        "bind" => Op::Bind {
            sasl: e
                .first_str("reqMethod")
                .is_some_and(|m| m.starts_with("SASL")),
        },
        "add" | "delete" | "modify" | "modrdn" => Op::Write,
        "unbind" => Op::Unbind,
        _ => Op::Other,
    };
    let start = e
        .first_str("reqStart")
        .and_then(time::parse_generalized)
        .ok_or(())?;
    // An oversized DN is replaced by a marker that is not a DN (never
    // parsed, never sliced; review L1): no naming context, `*` objects, and
    // a fingerprinted principal for a bind.
    let target = Zeroizing::new(match e.first_str("reqDN") {
        Some(d) if d.len() > dn::MAX_DN_BYTES => OVERSIZED_DN.to_owned(),
        Some(d) => d.to_owned(),
        None => String::new(),
    });
    let target_canon = Zeroizing::new(dn::canon(&target).unwrap_or_default());
    let authz = match e.first_str("reqAuthzID") {
        Some(a) if !a.trim().is_empty() => Some(Zeroizing::new(dn::canon(a).ok_or(())?)),
        _ => None,
    };
    let result = match op {
        Op::Unbind | Op::Other => 0,
        _ => u32::try_from(number(e, "reqResult").ok_or(())?).map_err(|_| ())?,
    };
    let scope = match e.first_str("reqScope") {
        Some("base") => Some(LogScope::Base),
        Some("one") => Some(LogScope::One),
        Some("sub") => Some(LogScope::Sub),
        Some("subord") => Some(LogScope::Subord),
        _ => None,
    };
    if op == Op::Search && scope.is_none() {
        return Err(());
    }
    let filter = e
        .values("reqFilter")
        .next()
        .map_or(Facts::UNKNOWN, filter::facts);
    Ok(Record {
        csn: csn.to_owned(),
        op,
        start,
        session: number(e, "reqSession").and_then(|s| u64::try_from(s).ok()),
        authz,
        target,
        target_canon,
        result,
        scope,
        filter,
        requested: requested(e),
        attrs_only: e.first_str("reqAttrsOnly") == Some("TRUE"),
        entries: number(e, "reqEntries").and_then(|n| u64::try_from(n).ok()),
        size_limit: number(e, "reqSizeLimit"),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::proto::Attribute;

    /// An accesslog entry for the tests.
    pub(crate) fn log_entry(attrs: &[(&str, &[&str])]) -> Entry {
        Entry {
            dn: Zeroizing::new("reqStart=20260929202642.000003Z,cn=accesslog".to_owned()),
            attributes: attrs
                .iter()
                .map(|(n, vs)| Attribute {
                    name: (*n).to_owned(),
                    values: vs
                        .iter()
                        .map(|v| Zeroizing::new(v.as_bytes().to_vec()))
                        .collect(),
                })
                .collect(),
            skipped: 0,
        }
    }

    pub(crate) const CSN: &str = "20260929202642.012954Z#000000#000#000000";

    #[test]
    fn a_search_record_keeps_closed_facts() {
        let e = log_entry(&[
            ("objectClass", &["auditSearch"]),
            ("reqStart", &["20260929202642.000003Z"]),
            ("reqType", &["search"]),
            ("reqSession", &["1000"]),
            (
                "reqAuthzID",
                &["cn=Databastion,ou=services,dc=example,dc=org"],
            ),
            ("reqDN", &["ou=People,dc=example,dc=org"]),
            ("reqResult", &["0"]),
            ("reqScope", &["sub"]),
            ("reqFilter", &["(mail=jane@example.org)"]),
            ("reqAttr", &["mail", "cn"]),
            ("reqAttrsOnly", &["FALSE"]),
            ("reqEntries", &["1"]),
            ("reqSizeLimit", &["500"]),
            ("entryCSN", &[CSN]),
        ]);
        let r = parse(&e).unwrap();
        assert_eq!(r.op, Op::Search);
        assert_eq!(r.scope, Some(LogScope::Sub));
        assert_eq!(r.session, Some(1000));
        assert_eq!(
            r.authz.as_ref().map(|a| a.as_str()),
            Some("cn=databastion,ou=services,dc=example,dc=org")
        );
        assert_eq!(r.target_canon.as_str(), "ou=people,dc=example,dc=org");
        assert_eq!(r.entries, Some(1));
        assert!(!r.filter.unselective);
        assert_eq!(r.requested.listed, 2);
        assert!(!r.requested.all_user && !r.requested.credential);
        // The filter value is in no field of the record.
        assert!(!format!("{r:?}").contains("jane"));
    }

    #[test]
    fn binds_writes_and_broken_records() {
        let bind = log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["bind"]),
            ("reqAuthzID", &[""]),
            ("reqDN", &["uid=nobody,dc=example,dc=org"]),
            ("reqResult", &["49"]),
            ("reqMethod", &["SIMPLE"]),
            ("entryCSN", &[CSN]),
        ]);
        let r = parse(&bind).unwrap();
        assert_eq!(r.op, Op::Bind { sasl: false });
        assert_eq!(r.result, 49);
        assert_eq!(r.authz, None);
        let sasl = log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["bind"]),
            ("reqResult", &["0"]),
            ("reqMethod", &["SASL(EXTERNAL)"]),
            ("entryCSN", &[CSN]),
        ]);
        assert_eq!(parse(&sasl).unwrap().op, Op::Bind { sasl: true });
        let unbind = log_entry(&[
            ("reqStart", &["20260929202642.000005Z"]),
            ("reqType", &["unbind"]),
            ("entryCSN", &[CSN]),
        ]);
        assert_eq!(parse(&unbind).unwrap().op, Op::Unbind);
        let ext = log_entry(&[
            ("reqStart", &["20260929202642.000005Z"]),
            ("reqType", &["extended1.3.6.1.4.1.4203.1.11.1"]),
            ("entryCSN", &[CSN]),
        ]);
        assert_eq!(parse(&ext).unwrap().op, Op::Other);
        // No CSN, a bad time, a search without scope, a bad result.
        for bad in [
            log_entry(&[("reqStart", &["20260929202642Z"]), ("reqType", &["unbind"])]),
            log_entry(&[
                ("reqStart", &["yesterday"]),
                ("reqType", &["unbind"]),
                ("entryCSN", &[CSN]),
            ]),
            log_entry(&[
                ("reqStart", &["20260929202642Z"]),
                ("reqType", &["search"]),
                ("reqResult", &["0"]),
                ("entryCSN", &[CSN]),
            ]),
            log_entry(&[
                ("reqStart", &["20260929202642Z"]),
                ("reqType", &["modify"]),
                ("reqResult", &["x"]),
                ("entryCSN", &[CSN]),
            ]),
        ] {
            assert!(parse(&bad).is_err());
        }
    }

    #[test]
    fn oversized_dns_are_replaced() {
        let long = format!("uid={},dc=x", "a".repeat(dn::MAX_DN_BYTES));
        let e = log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["bind"]),
            ("reqDN", &[long.as_str()]),
            ("reqResult", &["0"]),
            ("entryCSN", &[CSN]),
        ]);
        let r = parse(&e).unwrap();
        assert_eq!(r.target.as_str(), OVERSIZED_DN);
        assert!(r.target_canon.is_empty());
    }

    #[test]
    fn requested_attributes() {
        let e = log_entry(&[("reqAttr", &["1.1"])]);
        assert!(requested(&e).none);
        let e = log_entry(&[("reqAttr", &["userPassword", "authPassword"])]);
        let r = requested(&e);
        assert!(r.credential && r.only_credential && !r.none);
        let e = log_entry(&[("reqAttr", &["*", "+"])]);
        let r = requested(&e);
        assert!(r.all_user && r.operational);
        let e = log_entry(&[]);
        assert!(requested(&e).all_user);
    }
}
