//! Closed facts from a logged search filter (`reqFilter`, RFC 4515 string
//! form as slapd writes it). The filter holds other users' assertion
//! values: it is read in memory only, reduced to the facts below, and
//! never kept, logged or sent (I2, ADR-0029 decision 7).
//!
//! - **Unselective**: the filter selects no entry by value: only presence
//!   tests and `objectClass` equality assertions, under `&` / `|` (an `&`
//!   of unselective parts, an `|` with an unselective part; `(&)` is
//!   true). Negations, substrings, orderings, approximate and extensible
//!   matches, and any other equality are selective. The bulk-search shape
//!   (decision 8).
//! - **Own filter**: the filter is exactly one of the connector's own
//!   (decision 9), compared case-insensitively; slapd prefixes attributes
//!   the schema does not know with `?`, which is ignored there.

use crate::catalog::CONTAINER_CLASSES;

/// Longest filter examined; longer ones are treated as selective.
const MAX_FILTER_BYTES: usize = 64 * 1024;
/// Deepest nesting examined.
const MAX_DEPTH: usize = 32;

/// Which of the connector's own filters a logged filter is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnFilter {
    /// `(objectClass=*)`.
    Everything,
    /// The container listing filter.
    Containers,
}

/// What the connector keeps of a filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Facts {
    pub(crate) unselective: bool,
    pub(crate) own: Option<OwnFilter>,
}

impl Facts {
    /// A filter that could not be read: selective, not the agent's.
    pub(crate) const UNKNOWN: Self = Self {
        unselective: false,
        own: None,
    };
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn eat(&mut self, b: u8) -> Option<()> {
        (self.s.get(self.pos) == Some(&b)).then(|| self.pos += 1)
    }

    /// `(…)`: whether it is unselective.
    fn filter(&mut self, depth: usize) -> Option<bool> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.eat(b'(')?;
        let r = match self.s.get(self.pos)? {
            b'&' => {
                self.pos += 1;
                let mut all = true;
                while self.s.get(self.pos) == Some(&b'(') {
                    all &= self.filter(depth + 1)?;
                }
                all
            }
            b'|' => {
                self.pos += 1;
                let mut any = false;
                while self.s.get(self.pos) == Some(&b'(') {
                    any |= self.filter(depth + 1)?;
                }
                any
            }
            b'!' => {
                self.pos += 1;
                self.filter(depth + 1)?;
                false
            }
            _ => self.item()?,
        };
        self.eat(b')')?;
        Some(r)
    }

    /// An item up to its closing parenthesis (not consumed).
    fn item(&mut self) -> Option<bool> {
        let start = self.pos;
        while !matches!(self.s.get(self.pos)?, b'=' | b'~' | b'<' | b'>' | b':') {
            self.pos += 1;
        }
        let attr = &self.s[start..self.pos];
        let attr = attr.strip_prefix(b"?").unwrap_or(attr);
        let op = self.s[self.pos];
        if op != b'=' {
            // `~=`, `<=`, `>=`, extensible: selective. Skip the value.
            self.skip_value()?;
            return Some(false);
        }
        self.pos += 1;
        let value_start = self.pos;
        self.skip_value()?;
        let value = &self.s[value_start..self.pos];
        if value == b"*" {
            return Some(true);
        }
        if value.contains(&b'*') || value.is_empty() {
            // Substring (or empty equality): selective.
            return Some(false);
        }
        Some(attr.eq_ignore_ascii_case(b"objectClass"))
    }

    fn skip_value(&mut self) -> Option<()> {
        loop {
            match self.s.get(self.pos)? {
                b')' => return Some(()),
                b'(' => return None,
                _ => self.pos += 1,
            }
        }
    }
}

/// The container listing filter, lowercase, as slapd logs it.
fn containers_text() -> String {
    let mut s = String::from("(|");
    for c in CONTAINER_CLASSES {
        s.push_str("(objectclass=");
        s.push_str(&c.to_ascii_lowercase());
        s.push(')');
    }
    s.push(')');
    s
}

/// The facts of a logged filter.
pub(crate) fn facts(raw: &[u8]) -> Facts {
    if raw.len() > MAX_FILTER_BYTES {
        return Facts::UNKNOWN;
    }
    let mut p = Parser { s: raw, pos: 0 };
    let unselective = match p.filter(0) {
        Some(u) if p.pos == raw.len() => u,
        _ => return Facts::UNKNOWN,
    };
    // Own filters: lowercase, `?` dropped after an opening parenthesis
    // (unknown attribute marker). A zeroized copy, compared then dropped.
    let mut lower = zeroize::Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut prev = 0u8;
    for &b in raw {
        if !(b == b'?' && prev == b'(') {
            lower.push(b.to_ascii_lowercase());
        }
        prev = b;
    }
    let own = if lower.as_slice() == b"(objectclass=*)" {
        Some(OwnFilter::Everything)
    } else if lower.as_slice() == containers_text().as_bytes() {
        Some(OwnFilter::Containers)
    } else {
        None
    };
    Facts { unselective, own }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(f: &str) -> bool {
        facts(f.as_bytes()).unselective
    }

    #[test]
    fn unselective_filters_select_nothing_by_value() {
        assert!(u("(objectClass=*)"));
        assert!(u("(mail=*)"));
        assert!(u("(&)"));
        assert!(u("(objectClass=inetOrgPerson)"));
        assert!(u("(&(objectClass=person)(mail=*))"));
        assert!(u("(|(objectClass=person)(uid=jdoe))"));
        assert!(u("(|(userPassword=*)(?authPassword=*))"));
        assert!(!u("(uid=jdoe)"));
        assert!(!u("(uid=a*)"));
        assert!(!u("(cn>=a)"));
        assert!(!u("(cn~=jane)"));
        assert!(!u("(!(uid=nobody))"));
        assert!(!u("(!(objectClass=*))"));
        assert!(!u("(&(objectClass=person)(uid=jdoe))"));
        assert!(!u("(|)"));
        assert!(!u("(cn:caseExactMatch:=x)"));
        assert!(!u("(objectClass=)"));
    }

    #[test]
    fn malformed_filters_are_unknown() {
        for f in [
            "",
            "(",
            "objectClass=*",
            "(uid=x",
            "(uid=x))",
            "(&(uid=x)",
            "(a(b)=c)",
        ] {
            assert_eq!(facts(f.as_bytes()), Facts::UNKNOWN, "{f}");
        }
        let deep = format!("{}(objectClass=*){}", "(&".repeat(40), ")".repeat(40));
        assert_eq!(facts(deep.as_bytes()), Facts::UNKNOWN);
    }

    #[test]
    fn own_filters_are_recognized_exactly() {
        assert_eq!(facts(b"(objectClass=*)").own, Some(OwnFilter::Everything));
        assert_eq!(facts(b"(OBJECTCLASS=*)").own, Some(OwnFilter::Everything));
        assert_eq!(
            facts(
                b"(|(objectClass=organizationalUnit)(objectClass=organization)\
                  (objectClass=dcObject)(objectClass=domain)(objectClass=country)\
                  (objectClass=locality))"
            )
            .own,
            Some(OwnFilter::Containers)
        );
        assert_eq!(facts(b"(objectClass=*?)").own, None);
        assert_eq!(facts(b"(mail=*)").own, None);
        assert_eq!(facts(b"(|(objectClass=organizationalUnit))").own, None);
    }
}
