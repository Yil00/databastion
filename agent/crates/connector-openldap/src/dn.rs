//! Distinguished names, handled in memory only (ADR-0029 decision 6).
//!
//! Entry DNs embed values (`uid=jdoe`, `cn=Jane Doe`): they never leave the
//! agent and are never logged. This module compares DNs (naming context
//! membership, the agent's own identity) and finds parents; what is sent
//! goes through `databastion_classifiers::names::normalize_ldap_dn`.

/// Longest DN examined; longer ones are treated as malformed.
pub(crate) const MAX_DN_BYTES: usize = 4096;
/// Most RDNs examined.
const MAX_RDNS: usize = 64;

/// The RDNs of `dn`, split at unescaped commas (RFC 4514: `\,` is part of
/// a value). `None` when empty, too long, with a dangling escape, or with
/// more than 64 RDNs.
pub(crate) fn rdns(dn: &str) -> Option<Vec<&str>> {
    if dn.is_empty() || dn.len() > MAX_DN_BYTES {
        return None;
    }
    let bytes = dn.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return None;
                }
                i += 2;
                continue;
            }
            b',' | b';' => {
                out.push(&dn[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&dn[start..]);
    if out.len() > MAX_RDNS || out.iter().any(|r| !r.contains('=')) {
        return None;
    }
    Some(out)
}

/// A comparable form of `dn`: RDNs trimmed, spaces around `=` and `+`
/// dropped, ASCII lowercased, joined with `,`. Attribute types and the
/// usual naming attributes (`dc`, `ou`, `cn`, `uid`, `o`) compare without
/// case in LDAP; other values may compare with case on the server, which
/// makes this form coarser, never finer. The empty DN (root DSE) is `""`.
pub(crate) fn canon(dn: &str) -> Option<String> {
    let dn = dn.trim();
    if dn.is_empty() {
        return Some(String::new());
    }
    let rdns = rdns(dn)?;
    let mut out = String::with_capacity(dn.len());
    for (n, rdn) in rdns.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        for (m, ava) in rdn.split('+').enumerate() {
            if m > 0 {
                out.push('+');
            }
            let (ty, value) = ava.split_once('=')?;
            out.push_str(&ty.trim().to_ascii_lowercase());
            out.push('=');
            out.push_str(&value.trim().to_ascii_lowercase());
        }
    }
    Some(out)
}

/// The parent of `dn` (everything after its first RDN), `None` for a
/// single RDN or a malformed DN.
pub(crate) fn parent(dn: &str) -> Option<&str> {
    let rdns = rdns(dn)?;
    if rdns.len() < 2 {
        return None;
    }
    let first = rdns[0].len();
    Some(dn[first + 1..].trim_start())
}

/// Whether the canonical DN `dn` is `base` or below it.
pub(crate) fn is_within(dn: &str, base: &str) -> bool {
    base.is_empty()
        || dn == base
        || (dn.len() > base.len()
            && dn.ends_with(base)
            && dn.as_bytes()[dn.len() - base.len() - 1] == b',')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdns_respect_escapes() {
        assert_eq!(
            rdns("cn=Doe\\, Jane,ou=people,dc=x").unwrap(),
            vec!["cn=Doe\\, Jane", "ou=people", "dc=x"]
        );
        assert!(rdns("cn=x\\").is_none());
        assert!(rdns("").is_none());
        assert!(rdns("novalue,dc=x").is_none());
        assert!(rdns(&"ou=a,".repeat(70)).is_none());
    }

    #[test]
    fn canonical_forms_compare_without_case_or_spaces() {
        assert_eq!(
            canon("CN=Databastion, OU=services,dc=Example , dc=org").unwrap(),
            "cn=databastion,ou=services,dc=example,dc=org"
        );
        assert_eq!(canon("uid=a + cn=b,dc=x").unwrap(), "uid=a+cn=b,dc=x");
        assert_eq!(canon("").unwrap(), "");
    }

    #[test]
    fn parents_and_membership() {
        assert_eq!(parent("uid=jdoe,ou=people,dc=x").unwrap(), "ou=people,dc=x");
        assert_eq!(parent("cn=a\\,b, ou=x").unwrap(), "ou=x");
        assert!(parent("dc=x").is_none());
        assert!(is_within(
            "ou=people,dc=example,dc=org",
            "dc=example,dc=org"
        ));
        assert!(is_within("dc=example,dc=org", "dc=example,dc=org"));
        assert!(!is_within("dc=myexample,dc=org", "example,dc=org"));
        assert!(!is_within("dc=org", "dc=example,dc=org"));
    }
}
