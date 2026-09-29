//! Property tests: hostile BER and LDAP input never panics and fails
//! closed; DN, attribute and filter handling never lets a value through
//! (I2).

use proptest::prelude::*;
use zeroize::Zeroizing;

use databastion_classifiers::names::{conforms, normalize_ldap_attribute, normalize_ldap_dn};

use crate::audit::{filter, records};
use crate::ber::{self, Reader};
use crate::proto::{self, Attribute, Entry, encode};
use crate::schema::Schema;
use crate::{dn, time};

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Mutations of a valid message: truncation, byte flips, insertions.
fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8, u8)]) -> Vec<u8> {
    for &(pos, kind, value) in edits {
        if bytes.is_empty() {
            break;
        }
        let i = pos % bytes.len();
        match kind % 4 {
            0 => bytes[i] = value,
            1 => bytes.truncate(i),
            2 => bytes.insert(i, value),
            _ => {
                bytes.remove(i);
            }
        }
    }
    bytes
}

fn walk(buf: &[u8]) {
    // Every element, recursively into constructed ones, bounded by the
    // input itself.
    let mut stack = vec![Reader::new(buf)];
    let mut steps = 0;
    while let Some(mut r) = stack.pop() {
        while !r.is_empty() && steps < 10_000 {
            steps += 1;
            match r.tlv() {
                Ok((tag, content)) => {
                    if tag & 0x20 != 0 {
                        stack.push(Reader::new(content));
                    } else if tag == ber::INTEGER {
                        let _ = ber::decode_int(content);
                    }
                }
                Err(_) => break,
            }
        }
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = proto::parse(&bytes);
        let _ = ber::message_len(&bytes);
        walk(&bytes);
    }

    #[test]
    fn mutated_messages_never_panic(
        values in proptest::collection::vec("[ -~]{0,40}", 0..6),
        edits in proptest::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 1..6),
        id in 1i32..1000,
    ) {
        let vals: Vec<&[u8]> = values.iter().map(|v| v.as_bytes()).collect();
        for msg in [
            encode::entry(id, "uid=x,ou=people,dc=example,dc=org", &[("mail", &vals), ("cn", &vals)]),
            encode::done(id, 0),
            encode::bind_response(id, 49),
            encode::extended_response(id, 0, Some(b"dn:cn=a")),
            encode::reference(id),
        ] {
            let bad = mutate(msg, &edits);
            if let Ok(m) = proto::parse(&bad) {
                // Whatever parsed has the id it claims and no negative one.
                prop_assert!(m.id >= 0);
            }
            if let Ok(Some(n)) = ber::message_len(&bad) {
                prop_assert!(n <= ber::MAX_MESSAGE);
            }
            walk(&bad);
        }
    }

    #[test]
    fn entry_dns_never_reach_a_container_name(
        uid in "[a-z0-9.@+-]{1,24}",
        person in "(Jane|Oliver|Marie|Pierre) [A-Z][a-z]{2,10}",
        phone in "0[1-9]( [0-9]{2}){4}",
        mail in "[a-z]{2,8}@[a-z]{2,8}\\.(com|org|fr)",
    ) {
        for container in [
            "ou=people,dc=example,dc=org".to_owned(),
            format!("ou={person},ou=teams,dc=example,dc=org"),
            format!("ou={phone},dc=example,dc=org"),
            format!("ou={mail},dc=example,dc=org"),
        ] {
            let entry = format!("uid={uid},{container}");
            for raw in [entry.as_str(), container.as_str()] {
                let name = normalize_ldap_dn(raw);
                prop_assert!(conforms(name.as_str()));
                // The entry's RDN never survives, nor do values that look
                // like data in a container.
                prop_assert!(!name.as_str().contains("uid="));
                for v in [&person, &phone, &mail] {
                    prop_assert!(!name.as_str().contains(v.as_str()), "{} kept", v);
                }
            }
            // The parent of an entry is its container, compared without
            // case.
            prop_assert_eq!(
                dn::canon(dn::parent(&entry).unwrap()),
                dn::canon(&container)
            );
        }
    }

    #[test]
    fn attribute_names_normalize_to_identifiers(raw in "[ -~]{1,64}") {
        let n = normalize_ldap_attribute(&raw);
        prop_assert!(conforms(n.as_str()));
        prop_assert!(!n.as_str().contains('@'));
    }

    #[test]
    fn dn_helpers_never_panic(raw in "\\PC{0,80}") {
        let _ = dn::rdns(&raw);
        let _ = dn::parent(&raw);
        if let Some(c) = dn::canon(&raw) {
            prop_assert!(dn::is_within(&c, &c));
        }
        let _ = time::parse_generalized(&raw);
        let _ = time::csn_time(&raw);
    }

    #[test]
    fn filters_never_panic_and_value_filters_are_selective(
        raw in "\\PC{0,120}",
        attr in "(uid|cn|mail|sn|telephoneNumber)",
        value in "[a-zA-Z0-9@. ]{1,20}",
        present in "(uid|cn|mail|objectClass)",
    ) {
        let _ = filter::facts(raw.as_bytes());
        let value_filter = format!("(&(objectClass=person)({attr}={value}))");
        prop_assert!(!filter::facts(value_filter.as_bytes()).unselective);
        let dump = format!("(|({present}=*)(objectClass={value}))");
        prop_assert!(filter::facts(dump.as_bytes()).unselective);
    }

    #[test]
    fn log_records_keep_no_filter_or_dn_text(
        filter_value in "[a-z]{6,12}@secret\\.example",
        dn_value in "[a-z]{6,12}SECRET",
        entries in 0u64..100_000,
    ) {
        let f = format!("(mail={filter_value})");
        let d = format!("uid={dn_value},ou=people,dc=example,dc=org");
        let entries = entries.to_string();
        let e = Entry {
            dn: Zeroizing::new("reqStart=20260929202642.000003Z,cn=accesslog".to_owned()),
            attributes: [
                ("reqStart", "20260929202642.000003Z"),
                ("reqType", "search"),
                ("reqAuthzID", "cn=app,dc=example,dc=org"),
                ("reqDN", d.as_str()),
                ("reqResult", "0"),
                ("reqScope", "sub"),
                ("reqFilter", f.as_str()),
                ("reqEntries", entries.as_str()),
                ("entryCSN", "20260929202642.012954Z#000000#000#000000"),
            ]
            .iter()
            .map(|(n, v)| Attribute {
                name: (*n).to_owned(),
                values: vec![Zeroizing::new(v.as_bytes().to_vec())],
            })
            .collect(),
            skipped: 0,
        };
        let r = records::parse(&e).unwrap();
        let shown = format!("{r:?}");
        prop_assert!(!shown.contains(&filter_value) && !shown.contains(&dn_value));
        prop_assert!(!r.filter.unselective);
    }

    #[test]
    fn schema_descriptions_never_panic(
        descriptions in proptest::collection::vec("\\PC{0,200}", 0..8),
    ) {
        let s = Schema::parse(
            descriptions.iter().map(|d| d.as_bytes()),
            descriptions.iter().map(|d| d.as_bytes()),
        );
        let (requested, _) = s.requested();
        for a in &requested {
            prop_assert!(s.eligible(a));
        }
    }
}

proptest! {
    #![proptest_config(config())]

    /// Security review H1: any UTF-8 in any log attribute (a hostile or
    /// broken server) is dropped or reduced, never a panic.
    #[test]
    fn log_records_with_arbitrary_text_never_panic(
        start in "(\\PC{0,24}|[0-9é.]{10,16}Z)",
        csn in "\\PC{0,48}",
        kind in "(search|bind|modify|unbind|\\PC{0,8})",
        dn in "\\PC{0,64}",
        authz in "\\PC{0,64}",
        filter in "\\PC{0,64}",
        numbers in proptest::collection::vec("\\PC{0,12}", 4),
        attrs in proptest::collection::vec("\\PC{0,16}", 0..4),
    ) {
        let csn_ok = "20260929202642.012954Z#000000#000#000000".to_owned();
        for (start, csn) in [(start.as_str(), csn.as_str()), (start.as_str(), csn_ok.as_str()), ("20260929202642Z", csn.as_str())] {
            let mut list: Vec<(&str, Vec<&str>)> = vec![
                ("reqStart", vec![start]),
                ("entryCSN", vec![csn]),
                ("reqType", vec![kind.as_str()]),
                ("reqDN", vec![dn.as_str()]),
                ("reqAuthzID", vec![authz.as_str()]),
                ("reqFilter", vec![filter.as_str()]),
                ("reqResult", vec![numbers[0].as_str()]),
                ("reqEntries", vec![numbers[1].as_str()]),
                ("reqSession", vec![numbers[2].as_str()]),
                ("reqSizeLimit", vec![numbers[3].as_str()]),
                ("reqScope", vec!["sub"]),
            ];
            list.push(("reqAttr", attrs.iter().map(String::as_str).collect()));
            let e = Entry {
                dn: Zeroizing::new(String::new()),
                attributes: list
                    .iter()
                    .map(|(n, vs)| Attribute {
                        name: (*n).to_owned(),
                        values: vs.iter().map(|v| Zeroizing::new(v.as_bytes().to_vec())).collect(),
                    })
                    .collect(),
                skipped: 0,
            };
            let _ = records::parse(&e);
            let _ = time::parse_generalized(start);
            let _ = time::csn_time(csn);
        }
    }
}
