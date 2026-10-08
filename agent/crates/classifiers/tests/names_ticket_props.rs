//! Property tests (PR #141 review M3): a CAS ticket id in a name (a
//! column, a field path, a MongoDB key, an LDAP attribute or DN) never
//! survives normalization, whatever surrounds it.

#![allow(clippy::unwrap_used)]

use databastion_classifiers::names::{
    PathPart, normalize_field_path, normalize_ldap_attribute, normalize_ldap_dn, normalize_path,
};
use proptest::prelude::*;

fn ticket() -> impl Strategy<Value = (String, String)> {
    (
        prop_oneof![
            "(TGT|ST|PT|PGT|PGTIOU|TST|OC|AT|RT|ODT|ODUC|CIBA|OPAR)",
            // The generic shape.
            "[A-Z]{2,8}",
        ],
        0u32..100_000,
        "[A-Za-z0-9]{4,24}(-cas[0-9]{1,2})?",
    )
        .prop_map(|(p, n, rest)| (format!("{p}-{n}-"), format!("{p}-{n}-{rest}")))
}

/// Text around a ticket in a name: never ends with a letter or digit
/// (a generic-shaped id glued to letters is not a ticket at a word start).
fn around() -> impl Strategy<Value = (String, String)> {
    (
        prop_oneof![Just(String::new()), "[a-z_]{1,10}[._/ ]"],
        prop_oneof![Just(String::new()), "[._][a-zA-Z0-9_.]{1,16}"],
    )
}

fn survives(out: &str, head: &str, id: &str) -> bool {
    out.contains(head) || out.contains(id)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn never_in_a_path((head, id) in ticket(), (pre, post) in around()) {
        let raw = format!("{pre}{id}{post}");
        let out = normalize_path(&raw);
        prop_assert!(!survives(out.as_str(), &head, &id), "{}", out.as_str());
    }

    #[test]
    fn never_in_a_field_path(
        (head, id) in ticket(),
        before in proptest::collection::vec("[a-z]{1,8}", 0..3),
        after in proptest::collection::vec("[a-zA-Z]{1,8}", 0..3),
        split in any::<bool>(),
    ) {
        // The id as one key, or split at its last `-` into nested keys.
        let mut parts: Vec<PathPart<'_>> = before.iter().map(|k| PathPart::Key(k)).collect();
        let cut = id.rfind('-').unwrap();
        let (a, b) = id.split_at(cut + 1);
        if split && !b.is_empty() {
            parts.push(PathPart::Key(a));
            parts.push(PathPart::Key(b));
        } else {
            parts.push(PathPart::Key(&id));
        }
        parts.extend(after.iter().map(|k| PathPart::Key(k)));
        let out = normalize_field_path(&parts);
        prop_assert!(!survives(out.as_str(), &head, &id), "{}", out.as_str());
    }

    #[test]
    fn never_in_ldap_names((head, id) in ticket(), (pre, post) in around()) {
        let attr = normalize_ldap_attribute(&format!("{pre}{id}{post}"));
        prop_assert!(!survives(attr.as_str(), &head, &id));
        prop_assert!(!survives(attr.as_str(), &head.to_ascii_lowercase(), &id.to_ascii_lowercase()));
        let dn = normalize_ldap_dn(&format!("cn=x,ou={id},dc=example,dc=org"));
        prop_assert!(!survives(dn.as_str(), &head, &id), "{}", dn.as_str());
    }
}
